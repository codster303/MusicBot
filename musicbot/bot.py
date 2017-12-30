import os
import sys
import time
import shlex
import shutil
import random
import inspect
import logging
import asyncio
import pathlib
import traceback

import aiohttp
import discord
import colorlog

from io import BytesIO, StringIO
from functools import wraps
from textwrap import dedent
from datetime import timedelta
from collections import defaultdict

from discord.enums import ChannelType
from discord.ext.commands.bot import _get_variable

from . import exceptions
from . import downloader

from .playlist import Playlist
from .player import MusicPlayer
from .entry import StreamPlaylistEntry
from .opus_loader import load_opus_lib
from .config import Config, ConfigDefaults
from .permissions import Permissions, PermissionsDefaults
from .constructs import SkipState, Response, VoiceStateUpdate
from .utils import load_file, write_file, sane_round_int, fixg, ftimedelta, _func_

from .constants import VERSION as BOTVERSION
from .constants import DISCORD_MSG_CHAR_LIMIT, AUDIO_CACHE_PATH


load_opus_lib()

log = logging.getLogger(__name__)


class MusicBot(discord.Client):
    def __init__(self, config_file=None, perms_file=None):
        if config_file is None:
            config_file = ConfigDefaults.options_file

        if perms_file is None:
            perms_file = PermissionsDefaults.perms_file

        self.players = {}
        self.exit_signal = None
        self.init_ok = False
        self.cached_app_info = None
        self.last_status = None

        self.config = Config(config_file)
        self.permissions = Permissions(perms_file, grant_all=[self.config.owner_id])

        self.blacklist = set(load_file(self.config.blacklist_file))
        self.autoplaylist = load_file(self.config.auto_playlist_file)

        self.aiolocks = defaultdict(asyncio.Lock)
        self.downloader = downloader.Downloader(download_folder='audio_cache')

        self._setup_logging()

        if not self.autoplaylist:
            log.warning("Autoplaylist is empty, disabling.")
            self.config.auto_playlist = False
        else:
            log.info("Loaded autoplaylist with {} entries".format(len(self.autoplaylist)))

        if self.blacklist:
            log.debug("Loaded blacklist with {} entries".format(len(self.blacklist)))

        # TODO: Do these properly
        ssd_defaults = {
            'last_np_msg': None,
            'auto_paused': False,
            'availability_paused': False
        }
        self.server_specific_data = defaultdict(ssd_defaults.copy)

        super().__init__()
        self.aiosession = aiohttp.ClientSession(loop=self.loop)
        self.http.user_agent += ' MusicBot/%s' % BOTVERSION

    def __del__(self):
        # These functions return futures but it doesn't matter
        try:    self.http.session.close()
        except: pass

        try:    self.aiosession.close()
        except: pass

        super().__init__()
        self.aiosession = aiohttp.ClientSession(loop=self.loop)
        self.http.user_agent += ' MusicBot/%s' % BOTVERSION

    # TODO: Add some sort of `denied` argument for a message to send when someone else tries to use it
    def owner_only(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Only allow the owner to use these commands
            orig_msg = _get_variable('message')

            if not orig_msg or orig_msg.author.id == self.config.owner_id:
                # noinspection PyCallingNonCallable
                return await func(self, *args, **kwargs)
            else:
                raise exceptions.PermissionsError("only the owner can use this command", expire_in=30)

        return wrapper

    def dev_only(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            orig_msg = _get_variable('message')

            if orig_msg.author.id in self.config.dev_ids:
                # noinspection PyCallingNonCallable
                return await func(self, *args, **kwargs)
            else:
                raise exceptions.PermissionsError("only dev users can use this command", expire_in=30)

        wrapper.dev_cmd = True
        return wrapper

    def ensure_appinfo(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            await self._cache_app_info()
            # noinspection PyCallingNonCallable
            return await func(self, *args, **kwargs)

        return wrapper

    def _get_owner(self, *, server=None, voice=False):
            return discord.utils.find(
                lambda m: m.id == self.config.owner_id and (m.voice_channel if voice else True),
                server.members if server else self.get_all_members()
            )

    def _delete_old_audiocache(self, path=AUDIO_CACHE_PATH):
        try:
            shutil.rmtree(path)
            return True
        except:
            try:
                os.rename(path, path + '__')
            except:
                return False
            try:
                shutil.rmtree(path)
            except:
                os.rename(path + '__', path)
                return False

        return True

    def _setup_logging(self):
        if len(logging.getLogger(__package__).handlers) > 1:
            log.debug("Skipping logger setup, already set up")
            return

        shandler = logging.StreamHandler(stream=sys.stdout)
        shandler.setFormatter(colorlog.LevelFormatter(
            fmt = {
                'DEBUG': '{log_color}[{levelname}:{module}] {message}',
                'INFO': '{log_color}{message}',
                'WARNING': '{log_color}{levelname}: {message}',
                'ERROR': '{log_color}[{levelname}:{module}] {message}',
                'CRITICAL': '{log_color}[{levelname}:{module}] {message}',

                'EVERYTHING': '{log_color}[{levelname}:{module}] {message}',
                'NOISY': '{log_color}[{levelname}:{module}] {message}',
                'VOICEDEBUG': '{log_color}[{levelname}:{module}][{relativeCreated:.9f}] {message}',
                'FFMPEG': '{log_color}[{levelname}:{module}][{relativeCreated:.9f}] {message}'
            },
            log_colors = {
                'DEBUG':    'cyan',
                'INFO':     'white',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red',

                'EVERYTHING': 'white',
                'NOISY':      'white',
                'FFMPEG':     'bold_purple',
                'VOICEDEBUG': 'purple',
        },
            style = '{',
            datefmt = ''
        ))
        shandler.setLevel(self.config.debug_level)
        logging.getLogger(__package__).addHandler(shandler)

        log.debug("Set logging level to {}".format(self.config.debug_level_str))

        if self.config.debug_mode:
            dlogger = logging.getLogger('discord')
            dlogger.setLevel(logging.DEBUG)
            dhandler = logging.FileHandler(filename='logs/discord.log', encoding='utf-8', mode='w')
            dhandler.setFormatter(logging.Formatter('{asctime}:{levelname}:{name}: {message}', style='{'))
            dlogger.addHandler(dhandler)

    @staticmethod
    def _check_if_empty(vchannel: discord.Channel, *, excluding_me=True, excluding_deaf=False):
        def check(member):
            if excluding_me and member == vchannel.server.me:
                return False

            if excluding_deaf and any([member.deaf, member.self_deaf]):
                return False

            return True

        return not sum(1 for m in vchannel.voice_members if check(m))


    async def _join_startup_channels(self, channels, *, autosummon=True):
        joined_servers = set()
        channel_map = {c.server: c for c in channels}

        def _autopause(player):
            if self._check_if_empty(player.voice_client.channel):
                log.info("Initial autopause in empty channel")

                player.pause()
                self.server_specific_data[player.voice_client.channel.server]['auto_paused'] = True

        for server in self.servers:
            if server.unavailable or server in channel_map:
                continue

            if server.me.voice_channel:
                log.info("Found resumable voice channel {0.server.name}/{0.name}".format(server.me.voice_channel))
                channel_map[server] = server.me.voice_channel

            if autosummon:
                owner = self._get_owner(server=server, voice=True)
                if owner:
                    log.info("Found owner in \"{}\"".format(owner.voice_channel.name))
                    channel_map[server] = owner.voice_channel

        for server, channel in channel_map.items():
            if server in joined_servers:
                log.info("Already joined a channel in \"{}\", skipping".format(server.name))
                continue

            if channel and channel.type == discord.ChannelType.voice:
                log.info("Attempting to join {0.server.name}/{0.name}".format(channel))

                chperms = channel.permissions_for(server.me)

                if not chperms.connect:
                    log.info("Cannot join channel \"{}\", no permission.".format(channel.name))
                    continue

                elif not chperms.speak:
                    log.info("Will not join channel \"{}\", no permission to speak.".format(channel.name))
                    continue

                try:
                    player = await self.get_player(channel, create=True, deserialize=self.config.persistent_queue)
                    joined_servers.add(server)

                    log.info("Joined {0.server.name}/{0.name}".format(channel))

                    if player.is_stopped:
                        player.play()

                    if self.config.auto_playlist and not player.playlist.entries:
                        await self.on_player_finished_playing(player)
                        if self.config.auto_pause:
                            player.once('play', lambda player, **_: _autopause(player))

                except Exception:
                    log.debug("Error joining {0.server.name}/{0.name}".format(channel), exc_info=True)
                    log.error("Failed to join {0.server.name}/{0.name}".format(channel))

            elif channel:
                log.warning("Not joining {0.server.name}/{0.name}, that's a text channel.".format(channel))

            else:
                log.warning("Invalid channel thing: {}".format(channel))

    async def _wait_delete_msg(self, message, after):
        await asyncio.sleep(after)
        await self.safe_delete_message(message, quiet=True)

    # TODO: Check to see if I can just move this to on_message after the response check
    async def _manual_delete_check(self, message, *, quiet=False):
        if self.config.delete_invoking:
            await self.safe_delete_message(message, quiet=quiet)

    async def _check_ignore_non_voice(self, msg):
        vc = msg.server.me.voice_channel

        # If we've connected to a voice chat and we're in the same voice channel
        if not vc or vc == msg.author.voice_channel:
            return True
        else:
            raise exceptions.PermissionsError(
                "you cannot use this command when not in the voice channel (%s)" % vc.name, expire_in=30)

    async def _cache_app_info(self, *, update=False):
        if not self.cached_app_info and not update and self.user.bot:
            log.debug("Caching app info")
            self.cached_app_info = await self.application_info()

        return self.cached_app_info


    async def remove_from_autoplaylist(self, song_url:str, *, ex:Exception=None, delete_from_ap=False):
        if song_url not in self.autoplaylist:
            log.debug("URL \"{}\" not in autoplaylist, ignoring".format(song_url))
            return

        async with self.aiolocks[_func_()]:
            self.autoplaylist.remove(song_url)
            log.info("Removing unplayable song from autoplaylist: %s" % song_url)

            with open(self.config.auto_playlist_removed_file, 'a', encoding='utf8') as f:
                f.write(
                    '# Entry removed {ctime}\n'
                    '# Reason: {ex}\n'
                    '{url}\n\n{sep}\n\n'.format(
                        ctime=time.ctime(),
                        ex=str(ex).replace('\n', '\n#' + ' ' * 10), # 10 spaces to line up with # Reason:
                        url=song_url,
                        sep='#' * 32
                ))

            if delete_from_ap:
                log.info("Updating autoplaylist")
                write_file(self.config.auto_playlist_file, self.autoplaylist)

    @ensure_appinfo
    async def generate_invite_link(self, *, permissions=discord.Permissions(70380544), server=None):
        return discord.utils.oauth_url(self.cached_app_info.id, permissions=permissions, server=server)


    async def join_voice_channel(self, channel):
        if isinstance(channel, discord.Object):
            channel = self.get_channel(channel.id)

        if getattr(channel, 'type', ChannelType.text) != ChannelType.voice:
            raise discord.InvalidArgument('Channel passed must be a voice channel')

        server = channel.server

        if self.is_voice_connected(server):
            raise discord.ClientException('Already connected to a voice channel in this server')

        def session_id_found(data):
            user_id = data.get('user_id')
            guild_id = data.get('guild_id')
            return user_id == self.user.id and guild_id == server.id

        log.voicedebug("(%s) creating futures", _func_())
        # register the futures for waiting
        session_id_future = self.ws.wait_for('VOICE_STATE_UPDATE', session_id_found)
        voice_data_future = self.ws.wait_for('VOICE_SERVER_UPDATE', lambda d: d.get('guild_id') == server.id)

        # "join" the voice channel
        log.voicedebug("(%s) setting voice state", _func_())
        await self.ws.voice_state(server.id, channel.id)

        log.voicedebug("(%s) waiting for session id", _func_())
        session_id_data = await asyncio.wait_for(session_id_future, timeout=15, loop=self.loop)

        # sometimes it gets stuck on this step.  Jake said to wait indefinitely.  To hell with that.
        log.voicedebug("(%s) waiting for voice data", _func_())
        data = await asyncio.wait_for(voice_data_future, timeout=15, loop=self.loop)

        kwargs = {
            'user': self.user,
            'channel': channel,
            'data': data,
            'loop': self.loop,
            'session_id': session_id_data.get('session_id'),
            'main_ws': self.ws
        }

        voice = discord.VoiceClient(**kwargs)
        try:
            log.voicedebug("(%s) connecting...", _func_())
            with aiohttp.Timeout(15):
                await voice.connect()

        except asyncio.TimeoutError as e:
            log.voicedebug("(%s) connection failed, disconnecting", _func_())
            try:
                await voice.disconnect()
            except:
                pass
            raise e

        log.voicedebug("(%s) connection successful", _func_())

        self.connection._add_voice_client(server.id, voice)
        return voice


    async def get_voice_client(self, channel: discord.Channel):
        if isinstance(channel, discord.Object):
            channel = self.get_channel(channel.id)

        if getattr(channel, 'type', ChannelType.text) != ChannelType.voice:
            raise AttributeError('Channel passed must be a voice channel')

        async with self.aiolocks[_func_() + ':' + channel.server.id]:
            if self.is_voice_connected(channel.server):
                return self.voice_client_in(channel.server)

            vc = None
            t0 = t1 = 0
            tries = 5

            for attempt in range(1, tries+1):
                log.debug("Connection attempt {} to {}".format(attempt, channel.name))
                t0 = time.time()

                try:
                    vc = await self.join_voice_channel(channel)
                    t1 = time.time()
                    break

                except asyncio.TimeoutError:
                    log.warning("Failed to connect, retrying ({}/{})".format(attempt, tries))

                    # TODO: figure out if I need this or not
                    # try:
                    #     await self.ws.voice_state(channel.server.id, None)
                    # except:
                    #     pass

                except:
                    log.exception("Unknown error attempting to connect to voice")

                await asyncio.sleep(0.5)

            if not vc:
                log.critical("Voice client is unable to connect, restarting...")
                await self.restart()

            log.debug("Connected in {:0.1f}s".format(t1-t0))
            log.info("Connected to {}/{}".format(channel.server, channel))

            vc.ws._keep_alive.name = 'VoiceClient Keepalive'

            return vc

    async def reconnect_voice_client(self, server, *, sleep=0.1, channel=None):
        log.debug("Reconnecting voice client on \"{}\"{}".format(
            server, ' to "{}"'.format(channel.name) if channel else ''))

        async with self.aiolocks[_func_() + ':' + server.id]:
            vc = self.voice_client_in(server)

            if not (vc or channel):
                return

            _paused = False
            player = self.get_player_in(server)

            if player and player.is_playing:
                log.voicedebug("(%s) Pausing", _func_())

                player.pause()
                _paused = True

            log.voicedebug("(%s) Disconnecting", _func_())

            try:
                await vc.disconnect()
            except:
                pass

            if sleep:
                log.voicedebug("(%s) Sleeping for %s", _func_(), sleep)
                await asyncio.sleep(sleep)

            if player:
                log.voicedebug("(%s) Getting voice client", _func_())

                if not channel:
                    new_vc = await self.get_voice_client(vc.channel)
                else:
                    new_vc = await self.get_voice_client(channel)

                log.voicedebug("(%s) Swapping voice client", _func_())
                await player.reload_voice(new_vc)

                if player.is_paused and _paused:
                    log.voicedebug("Resuming")
                    player.resume()

        log.debug("Reconnected voice client on \"{}\"{}".format(
            server, ' to "{}"'.format(channel.name) if channel else ''))

    async def disconnect_voice_client(self, server):
        vc = self.voice_client_in(server)
        if not vc:
            return

        if server.id in self.players:
            self.players.pop(server.id).kill()

        await vc.disconnect()

    async def disconnect_all_voice_clients(self):
        for vc in list(self.voice_clients).copy():
            await self.disconnect_voice_client(vc.channel.server)

    async def set_voice_state(self, vchannel, *, mute=False, deaf=False):
        if isinstance(vchannel, discord.Object):
            vchannel = self.get_channel(vchannel.id)

        if getattr(vchannel, 'type', ChannelType.text) != ChannelType.voice:
            raise AttributeError('Channel passed must be a voice channel')

        await self.ws.voice_state(vchannel.server.id, vchannel.id, mute, deaf)
        # I hope I don't have to set the channel here
        # instead of waiting for the event to update it

    def get_player_in(self, server: discord.Server) -> MusicPlayer:
        return self.players.get(server.id)

    async def get_player(self, channel, create=False, *, deserialize=False) -> MusicPlayer:
        server = channel.server

        async with self.aiolocks[_func_() + ':' + server.id]:
            if deserialize:
                voice_client = await self.get_voice_client(channel)
                player = await self.deserialize_queue(server, voice_client)

                if player:
                    log.debug("Created player via deserialization for server %s with %s entries", server.id, len(player.playlist))
                    # Since deserializing only happens when the bot starts, I should never need to reconnect
                    return self._init_player(player, server=server)

            if server.id not in self.players:
                if not create:
                    raise exceptions.CommandError(
                        'The bot is not in a voice channel.  '
                        'Use %ssummon to summon it to your voice channel.' % self.config.command_prefix)

                voice_client = await self.get_voice_client(channel)

                playlist = Playlist(self)
                player = MusicPlayer(self, voice_client, playlist)
                self._init_player(player, server=server)

            async with self.aiolocks[self.reconnect_voice_client.__name__ + ':' + server.id]:
                if self.players[server.id].voice_client not in self.voice_clients:
                    log.debug("Reconnect required for voice client in {}".format(server.name))
                    await self.reconnect_voice_client(server, channel=channel)

        return self.players[server.id]

    def _init_player(self, player, *, server=None):
        player = player.on('play', self.on_player_play) \
                       .on('resume', self.on_player_resume) \
                       .on('pause', self.on_player_pause) \
                       .on('stop', self.on_player_stop) \
                       .on('finished-playing', self.on_player_finished_playing) \
                       .on('entry-added', self.on_player_entry_added) \
                       .on('error', self.on_player_error)

        player.skip_state = SkipState()

        if server:
            self.players[server.id] = player

        return player

    async def on_player_play(self, player, entry):
        await self.update_now_playing_status(entry)
        player.skip_state.reset()

        # This is the one event where its ok to serialize autoplaylist entries
        await self.serialize_queue(player.voice_client.channel.server)

        channel = entry.meta.get('channel', None)
        author = entry.meta.get('author', None)

        if channel and author:
            last_np_msg = self.server_specific_data[channel.server]['last_np_msg']
            if last_np_msg and last_np_msg.channel == channel:

                async for lmsg in self.logs_from(channel, limit=1):
                    if lmsg != last_np_msg and last_np_msg:
                        await self.safe_delete_message(last_np_msg)
                        self.server_specific_data[channel.server]['last_np_msg'] = None
                    break  # This is probably redundant

            if self.config.now_playing_mentions:
                newmsg = '%s - your song **%s** is now playing in %s!' % (
                    entry.meta['author'].mention, entry.title, player.voice_client.channel.name)
            else:
                newmsg = 'Now playing in %s: **%s**' % (
                    player.voice_client.channel.name, entry.title)

            if self.server_specific_data[channel.server]['last_np_msg']:
                self.server_specific_data[channel.server]['last_np_msg'] = await self.safe_edit_message(last_np_msg, newmsg, send_if_fail=True)
            else:
                self.server_specific_data[channel.server]['last_np_msg'] = await self.safe_send_message(channel, newmsg)

        # TODO: Check channel voice state?

    async def on_player_resume(self, player, entry, **_):
        await self.update_now_playing_status(entry)

    async def on_player_pause(self, player, entry, **_):
        await self.update_now_playing_status(entry, True)
        # await self.serialize_queue(player.voice_client.channel.server)

    async def on_player_stop(self, player, **_):
        await self.update_now_playing_status()

    async def on_player_finished_playing(self, player, **_):
        if not player.playlist.entries and not player.current_entry and self.config.auto_playlist:
            while self.autoplaylist:
                random.shuffle(self.autoplaylist)
                song_url = random.choice(self.autoplaylist)

                info = {}

                try:
                    info = await self.downloader.extract_info(player.playlist.loop, song_url, download=False, process=False)
                except downloader.youtube_dl.utils.DownloadError as e:
                    if 'YouTube said:' in e.args[0]:
                        # url is bork, remove from list and put in removed list
                        log.error("Error processing youtube url:\n{}".format(e.args[0]))

                    else:
                        # Probably an error from a different extractor, but I've only seen youtube's
                        log.error("Error processing \"{url}\": {ex}".format(url=song_url, ex=e))

                    await self.remove_from_autoplaylist(song_url, ex=e, delete_from_ap=True)
                    continue

                except Exception as e:
                    log.error("Error processing \"{url}\": {ex}".format(url=song_url, ex=e))
                    log.exception()

                    self.autoplaylist.remove(song_url)
                    continue

                if info.get('entries', None):  # or .get('_type', '') == 'playlist'
                    log.debug("Playlist found but is unsupported at this time, skipping.")
                    # TODO: Playlist expansion

                # Do I check the initial conditions again?
                # not (not player.playlist.entries and not player.current_entry and self.config.auto_playlist)

                try:
                    await player.playlist.add_entry(song_url, channel=None, author=None)
                except exceptions.ExtractionError as e:
                    log.error("Error adding song from autoplaylist: {}".format(e))
                    log.debug('', exc_info=True)
                    continue

                break

            if not self.autoplaylist:
                # TODO: When I add playlist expansion, make sure that's not happening during this check
                log.warning("No playable songs in the autoplaylist, disabling.")
                self.config.auto_playlist = False

        else: # Don't serialize for autoplaylist events
            await self.serialize_queue(player.voice_client.channel.server)

    async def on_player_entry_added(self, player, playlist, entry, **_):
        if entry.meta.get('author') and entry.meta.get('channel'):
            await self.serialize_queue(player.voice_client.channel.server)

    async def on_player_error(self, player, entry, ex, **_):
        if 'channel' in entry.meta:
            await self.safe_send_message(
                entry.meta['channel'],
                "```\nError from FFmpeg:\n{}\n```".format(ex)
            )
        else:
            log.exception("Player error", exc_info=ex)

    async def update_now_playing_status(self, entry=None, is_paused=False):
        game = None

        if self.user.bot:
            activeplayers = sum(1 for p in self.players.values() if p.is_playing)
            if activeplayers > 1:
                game = discord.Game(name="music on %s servers" % activeplayers)
                entry = None

            elif activeplayers == 1:
                player = discord.utils.get(self.players.values(), is_playing=True)
                entry = player.current_entry

        if entry:
            prefix = u'\u275A\u275A ' if is_paused else ''

            name = u'{}{}'.format(prefix, entry.title)[:128]
            game = discord.Game(name=name)

        async with self.aiolocks[_func_()]:
            if game != self.last_status:
                await self.change_presence(game=game)
                self.last_status = game

    async def update_now_playing_message(self, server, message, *, channel=None):
        lnp = self.server_specific_data[server]['last_np_msg']
        m = None

        if message is None and lnp:
            await self.safe_delete_message(lnp, quiet=True)

        elif lnp: # If there was a previous lp message
            oldchannel = lnp.channel

            if lnp.channel == oldchannel: # If we have a channel to update it in
                async for lmsg in self.logs_from(channel, limit=1):
                    if lmsg != lnp and lnp: # If we need to resend it
                        await self.safe_delete_message(lnp, quiet=True)
                        m = await self.safe_send_message(channel, message, quiet=True)
                    else:
                        m = await self.safe_edit_message(lnp, message, send_if_fail=True, quiet=False)

            elif channel: # If we have a new channel to send it to
                await self.safe_delete_message(lnp, quiet=True)
                m = await self.safe_send_message(channel, message, quiet=True)

            else: # we just resend it in the old channel
                await self.safe_delete_message(lnp, quiet=True)
                m = await self.safe_send_message(oldchannel, message, quiet=True)

        elif channel: # No previous message
            m = await self.safe_send_message(channel, message, quiet=True)

        self.server_specific_data[server]['last_np_msg'] = m


    async def serialize_queue(self, server, *, dir=None):
        """
        Serialize the current queue for a server's player to json.
        """

        player = self.get_player_in(server)
        if not player:
            return

        if dir is None:
            dir = 'data/%s/queue.json' % server.id

        async with self.aiolocks['queue_serialization'+':'+server.id]:
            log.debug("Serializing queue for %s", server.id)

            with open(dir, 'w', encoding='utf8') as f:
                f.write(player.serialize(sort_keys=True))

    async def serialize_all_queues(self, *, dir=None):
        coros = [self.serialize_queue(s, dir=dir) for s in self.servers]
        await asyncio.gather(*coros, return_exceptions=True)

    async def deserialize_queue(self, server, voice_client, playlist=None, *, dir=None) -> MusicPlayer:
        """
        Deserialize a saved queue for a server into a MusicPlayer.  If no queue is saved, returns None.
        """

        if playlist is None:
            playlist = Playlist(self)

        if dir is None:
            dir = 'data/%s/queue.json' % server.id

        async with self.aiolocks['queue_serialization' + ':' + server.id]:
            if not os.path.isfile(dir):
                return None

            log.debug("Deserializing queue for %s", server.id)

            with open(dir, 'r', encoding='utf8') as f:
                data = f.read()

        return MusicPlayer.from_json(data, self, voice_client, playlist)

    @ensure_appinfo
    async def _on_ready_sanity_checks(self):
        # Ensure folders exist
        await self._scheck_ensure_env()

        # Server permissions check
        await self._scheck_server_permissions()

        # playlists in autoplaylist
        await self._scheck_autoplaylist()

        # config/permissions async validate?
        await self._scheck_configs()


    async def _scheck_ensure_env(self):
        log.debug("Ensuring data folders exist")
        for server in self.servers:
            pathlib.Path('data/%s/' % server.id).mkdir(exist_ok=True)

        with open('data/server_names.txt', 'w', encoding='utf8') as f:
            for server in sorted(self.servers, key=lambda s:int(s.id)):
                f.write('{:<22} {}\n'.format(server.id, server.name))

        if not self.config.save_videos and os.path.isdir(AUDIO_CACHE_PATH):
            if self._delete_old_audiocache():
                log.debug("Deleted old audio cache")
            else:
                log.debug("Could not delete old audio cache, moving on.")


    async def _scheck_server_permissions(self):
        log.debug("Checking server permissions")
        pass # TODO

    async def _scheck_autoplaylist(self):
        log.debug("Auditing autoplaylist")
        pass # TODO

    async def _scheck_configs(self):
        log.debug("Validating config")
        await self.config.async_validate(self)

        log.debug("Validating permissions config")
        await self.permissions.async_validate(self)



#######################################################################################################################


    async def safe_send_message(self, dest, content, **kwargs):
        tts = kwargs.pop('tts', False)
        quiet = kwargs.pop('quiet', False)
        expire_in = kwargs.pop('expire_in', 0)
        allow_none = kwargs.pop('allow_none', True)
        also_delete = kwargs.pop('also_delete', None)

        msg = None
        lfunc = log.debug if quiet else log.warning

        try:
            if content is not None or allow_none:
                msg = await self.send_message(dest, content, tts=tts)

        except discord.Forbidden:
            lfunc("Cannot send message to \"%s\", no permission", dest.name)

        except discord.NotFound:
            lfunc("Cannot send message to \"%s\", invalid channel?", dest.name)

        except discord.HTTPException:
            if len(content) > DISCORD_MSG_CHAR_LIMIT:
                lfunc("Message is over the message size limit (%s)", DISCORD_MSG_CHAR_LIMIT)
            else:
                lfunc("Failed to send message")
                log.noise("Got HTTPException trying to send message to %s: %s", dest, content)

        finally:
            if msg and expire_in:
                asyncio.ensure_future(self._wait_delete_msg(msg, expire_in))

            if also_delete and isinstance(also_delete, discord.Message):
                asyncio.ensure_future(self._wait_delete_msg(also_delete, expire_in))

        return msg

    async def safe_delete_message(self, message, *, quiet=False):
        lfunc = log.debug if quiet else log.warning

        try:
            return await self.delete_message(message)

        except discord.Forbidden:
            lfunc("Cannot delete message \"{}\", no permission".format(message.clean_content))

        except discord.NotFound:
            lfunc("Cannot delete message \"{}\", message not found".format(message.clean_content))

    async def safe_edit_message(self, message, new, *, send_if_fail=False, quiet=False):
        lfunc = log.debug if quiet else log.warning

        try:
            return await self.edit_message(message, new)

        except discord.NotFound:
            lfunc("Cannot edit message \"{}\", message not found".format(message.clean_content))
            if send_if_fail:
                lfunc("Sending message instead")
                return await self.safe_send_message(message.channel, new)

    async def send_typing(self, destination):
        try:
            return await super().send_typing(destination)
        except discord.Forbidden:
            log.warning("Could not send typing to {}, no permission".format(destination))

    async def edit_profile(self, **fields):
        if self.user.bot:
            return await super().edit_profile(**fields)
        else:
            return await super().edit_profile(self.config._password,**fields)


    async def restart(self):
        self.exit_signal = exceptions.RestartSignal()
        await self.logout()

    def restart_threadsafe(self):
        asyncio.run_coroutine_threadsafe(self.restart(), self.loop)

    def _cleanup(self):
        try:
            self.loop.run_until_complete(self.logout())
        except: pass

        pending = asyncio.Task.all_tasks()
        gathered = asyncio.gather(*pending)

        try:
            gathered.cancel()
            self.loop.run_until_complete(gathered)
            gathered.exception()
        except: pass

    # noinspection PyMethodOverriding
    def run(self):
        try:
            self.loop.run_until_complete(self.start(*self.config.auth))

        except discord.errors.LoginFailure:
            # Add if token, else
            raise exceptions.HelpfulError(
                "Bot cannot login, bad credentials.",
                "Fix your %s in the options file.  "
                "Remember that each field should be on their own line."
                % ['shit', 'Token', 'Email/Password', 'Credentials'][len(self.config.auth)]
            ) #     ^^^^ In theory self.config.auth should never have no items

        finally:
            try:
                self._cleanup()
            except Exception:
                log.error("Error in cleanup", exc_info=True)

            self.loop.close()
            if self.exit_signal:
                raise self.exit_signal

    async def logout(self):
        await self.disconnect_all_voice_clients()
        return await super().logout()

    async def on_error(self, event, *args, **kwargs):
        ex_type, ex, stack = sys.exc_info()

        if ex_type == exceptions.HelpfulError:
            log.error("Exception in {}:\n{}".format(event, ex.message))

            await asyncio.sleep(2)  # don't ask
            await self.logout()

        elif issubclass(ex_type, exceptions.Signal):
            self.exit_signal = ex_type
            await self.logout()

        else:
            log.error("Exception in {}".format(event), exc_info=True)

    async def on_resumed(self):
        log.info("\nReconnected to discord.\n")

    async def on_ready(self):
        dlogger = logging.getLogger('discord')
        for h in dlogger.handlers:
            if getattr(h, 'terminator', None) == '':
                dlogger.removeHandler(h)
                print()

        log.debug("Connection established, ready to go.")

        self.ws._keep_alive.name = 'Gateway Keepalive'

        if self.init_ok:
            log.debug("Received additional READY event, may have failed to resume")
            return

        await self._on_ready_sanity_checks()
        print()

        log.info('Connected!  Musicbot v{}\n'.format(BOTVERSION))

        self.init_ok = True

        ################################

        log.info("Bot:   {0}/{1}#{2}{3}".format(
            self.user.id,
            self.user.name,
            self.user.discriminator,
            ' [BOT]' if self.user.bot else ' [Userbot]'
        ))

        owner = self._get_owner(voice=True) or self._get_owner()
        if owner and self.servers:
            log.info("Owner: {0}/{1}#{2}\n".format(
                owner.id,
                owner.name,
                owner.discriminator
            ))

            log.info('Server List:')
            [log.info(' - ' + s.name) for s in self.servers]

        elif self.servers:
            log.warning("Owner could not be found on any server (id: %s)\n" % self.config.owner_id)

            log.info('Server List:')
            [log.info(' - ' + s.name) for s in self.servers]

        else:
            log.warning("Owner unknown, bot is not on any servers.")
            if self.user.bot:
                log.warning(
                    "To make the bot join a server, paste this link in your browser. \n"
                    "Note: You should be logged into your main account and have \n"
                    "manage server permissions on the server you want the bot to join.\n"
                    "  " + await self.generate_invite_link()
                )

        print(flush=True)

        if self.config.bound_channels:
            chlist = set(self.get_channel(i) for i in self.config.bound_channels if i)
            chlist.discard(None)

            invalids = set()
            invalids.update(c for c in chlist if c.type == discord.ChannelType.voice)

            chlist.difference_update(invalids)
            self.config.bound_channels.difference_update(invalids)

            if chlist:
                log.info("Bound to text channels:")
                [log.info(' - {}/{}'.format(ch.server.name.strip(), ch.name.strip())) for ch in chlist if ch]
            else:
                print("Not bound to any text channels")

            if invalids and self.config.debug_mode:
                print(flush=True)
                log.info("Not binding to voice channels:")
                [log.info(' - {}/{}'.format(ch.server.name.strip(), ch.name.strip())) for ch in invalids if ch]

            print(flush=True)

        else:
            log.info("Not bound to any text channels")

        if self.config.autojoin_channels:
            chlist = set(self.get_channel(i) for i in self.config.autojoin_channels if i)
            chlist.discard(None)

            invalids = set()
            invalids.update(c for c in chlist if c.type == discord.ChannelType.text)

            chlist.difference_update(invalids)
            self.config.autojoin_channels.difference_update(invalids)

            if chlist:
                log.info("Autojoining voice chanels:")
                [log.info(' - {}/{}'.format(ch.server.name.strip(), ch.name.strip())) for ch in chlist if ch]
            else:
                log.info("Not autojoining any voice channels")

            if invalids and self.config.debug_mode:
                print(flush=True)
                log.info("Cannot autojoin text channels:")
                [log.info(' - {}/{}'.format(ch.server.name.strip(), ch.name.strip())) for ch in invalids if ch]

            autojoin_channels = chlist

        else:
            log.info("Not autojoining any voice channels")
            autojoin_channels = set()

        print(flush=True)
        log.info("Options:")

        log.info("  Command prefix: " + self.config.command_prefix)
        log.info("  Default volume: {}%".format(int(self.config.default_volume * 100)))
        log.info("  Skip threshold: {} votes or {}%".format(
            self.config.skips_required, fixg(self.config.skip_ratio_required * 100)))
        log.info("  Now Playing @mentions: " + ['Disabled', 'Enabled'][self.config.now_playing_mentions])
        log.info("  Auto-Summon: " + ['Disabled', 'Enabled'][self.config.auto_summon])
        log.info("  Auto-Playlist: " + ['Disabled', 'Enabled'][self.config.auto_playlist])
        log.info("  Auto-Pause: " + ['Disabled', 'Enabled'][self.config.auto_pause])
        log.info("  Delete Messages: " + ['Disabled', 'Enabled'][self.config.delete_messages])
        if self.config.delete_messages:
            log.info("    Delete Invoking: " + ['Disabled', 'Enabled'][self.config.delete_invoking])
        log.info("  Debug Mode: " + ['Disabled', 'Enabled'][self.config.debug_mode])
        log.info("  Downloaded songs will be " + ['deleted', 'saved'][self.config.save_videos])
        print(flush=True)

        # maybe option to leave the ownerid blank and generate a random command for the owner to use
        # wait_for_message is pretty neato

        await self._join_startup_channels(autojoin_channels, autosummon=self.config.auto_summon)

        # t-t-th-th-that's all folks!

    async def cmd_help(self, command=None):
        """
        Usage:
            {command_prefix}help [command]

        Prints a help message.
        If a command is specified, it prints a help message for that command.
        Otherwise, it lists the available commands.
        """

        if command:
            cmd = getattr(self, 'cmd_' + command, None)
            if cmd and not hasattr(cmd, 'dev_cmd'):
                return Response(
                    "```\n{}```".format(
                        dedent(cmd.__doc__)
                    ).format(command_prefix=self.config.command_prefix),
                    delete_after=60
                )
            else:
                return Response("No such command", delete_after=10)

        else:
            helpmsg = "**Available commands**\n```"
            commands = []

            for att in dir(self):
                if att.startswith('cmd_') and att != 'cmd_help' and not hasattr(getattr(self, att), 'dev_cmd'):
                    command_name = att.replace('cmd_', '').lower()
                    commands.append("{}{}".format(self.config.command_prefix, command_name))

            helpmsg += ", ".join(commands)
            helpmsg += "```\n<https://github.com/SexualRhinoceros/MusicBot/wiki/Commands-list>"
            helpmsg += "You can also use `{}help x` for more info about each command.".format(self.config.command_prefix)

            return Response(helpmsg, reply=True, delete_after=60)

    async def cmd_blacklist(self, message, user_mentions, option, something):
        """
        Usage:
            {command_prefix}blacklist [ + | - | add | remove ] @UserName [@UserName2 ...]

        Add or remove users to the blacklist.
        Blacklisted users are forbidden from using bot commands.
        """

        if not user_mentions:
            raise exceptions.CommandError("No users listed.", expire_in=20)

        if option not in ['+', '-', 'add', 'remove']:
            raise exceptions.CommandError(
                'Invalid option "%s" specified, use +, -, add, or remove' % option, expire_in=20
            )

        for user in user_mentions.copy():
            if user.id == self.config.owner_id:
                print("[Commands:Blacklist] The owner cannot be blacklisted.")
                user_mentions.remove(user)

        old_len = len(self.blacklist)

        if option in ['+', 'add']:
            self.blacklist.update(user.id for user in user_mentions)

            write_file(self.config.blacklist_file, self.blacklist)

            return Response(
                '%s users have been added to the blacklist' % (len(self.blacklist) - old_len),
                reply=True, delete_after=10
            )

        else:
            if self.blacklist.isdisjoint(user.id for user in user_mentions):
                return Response('none of those users are in the blacklist.', reply=True, delete_after=10)

            else:
                self.blacklist.difference_update(user.id for user in user_mentions)
                write_file(self.config.blacklist_file, self.blacklist)

                return Response(
                    '%s users have been removed from the blacklist' % (old_len - len(self.blacklist)),
                    reply=True, delete_after=10
                )

   
    async def cmd_s(self, channel):
		await self.safe_send_message(channel, 
		"You have started searching for a song to play\nPlease select an artist:\n!s1 = Greydon Square\n!s2 = Scientifik\n!s3 = Sai Phi\n!s4 = Tombstone Da Deadman\n!s5 = Syqnys\n!s6 = SPAN PHLY\n!s7 = C Gats\n!s8 = The Twelfth Doctor\n!s9 = Low Technology")
		return
		
	async def cmd_s1(self, channel):
		await self.safe_send_message(channel,"You selected Greydon Square"\
		"\nPlease select an album:" \
		"\n!s1a = Omniverse : Type 3 : Aum niverse"\
		"\n!s1b = Type II : The Mandelbrot Set" \
		"\n!s1c = Type I : The Kardashev Scale" \
		"\n!s1d = The Cpt Theorem" \
		"\n!s1e = The Compton Effect")
		return
		
	async def cmd_s2(self, channel):
		await self.safe_send_message(channel,"You selected Scientifik\nPlease select a song:\n!s2a1 = Information Audio\n!s2a2 = Sisters & Brothers\n!s2a3 = 4 Minutes 20 Seconds\n!s2a4 = Spend A Lot of Time\n!s2a5 = Police and Thiefs\n!s2a6 = Caught Up\n!s1a7 = Lies \n!s2a8 = Take Advantage\n!s2a9 = Sometimes\n!s2a10 = Smiling Faces\n!s2a11 = Do What You Want\n!s2a12 = Watch Where I Go\n!s2a13 = Misunderstood (feat. Greydon Square)")
		return
	async def cmd_s3(self, channel):
		await self.safe_send_message(channel,"You selected Sai Phi\nPlease select a Song:\n !s3a1 = I Wrote This for The Universe\n !s3a2 = Sneek Peek of Upcoming Album") #\n !s3a1 = \n !s3a1 = \n !s3a1 = \n !s3a1 = \n !s3a1 = \n !s3a1 = \n !s3a1 = ")
		return
	async def cmd_s4(self, channel):
		await self.safe_send_message(channel,"You selected Tombstone Da Deadman\nPlease select an album:\n!s4a = Rise of The Reapers\n!s4b = The 6th Extinction")#\n!s1c = Type I : The Kardashev Scale\n!s1d = Tombstone Da Deadman\n!s1 = Syqnys\n!s1 = C Gats\n!s1 = SPAN PHLY\n")
		return
	async def cmd_s5(self, channel):
		await self.safe_send_message(channel,"You selected Syqnys\nPlease select an album:\n!s5a = VI. Syqs\n!s5b = IV. The Nausea\n!s5c = V. Chasing the Rabbit\n!s5d = III. Hypatia's Reign\n!s5e = II. CandyCap Rap and the L8Gr8 Atheist: Why Syqnys is the Future of Rap and Starving Children Taste Good")#\n!s1b = Type II : The Mandelbrot Set\n!s1c = Type I : The Kardashev Scale\n!s1d = Tombstone Da Deadman\n!s1 = Syqnys\n!s1 = C Gats\n!s1 = SPAN PHLY\n")
		return
	async def cmd_s7(self, channel):
		await self.safe_send_message(channel,"You selected C Gats\nPlease select an album:\n!s1a = GatZilla (C​-​Gats & Zpu​-​Zilla) - Attack on Titan\n!s1b = C Gats & Charlie Rose - Something Time Forgot: The Lost Mixtape\n!s7c = Passion & Progress Vol. 2: Therapeutic Music\n!s7d = Passion & Progress Vol. 1\n")
		return
	async def cmd_s6(self, channel):
		await self.safe_send_message(channel,"You selected SPAN PHLY\nPlease select an album:\n!s6a = Prelude to Perfection\n!s6b = Talking to Myself\n!s6c = Nothing Lasts Forever\n!s6d = Lengthen the Lifespan\n!s6e = Two Weeks Notice: Deluxe Edition\n\n")
		return
	async def cmd_s8(self, channel):
		await self.safe_send_message(channel,"You selected The Twelfth Doctor\nPlease select an album:\n!s8a = No Gods No Kings Only Timelords")
		return
	async def cmd_s9a(self, channel):
		await self.safe_send_message(channel,"You selected Low Technology\nPlease select an album:\n!s9 = LTGU")
		return
		
	async def cmd_s1a(self, channel):
		await self.safe_send_message(channel,"You selected Type 3 : Aum niverse by Greydon Square"\
		"\nPlease select a song:\n!s1a1 = Cosmic Harvest"\
		"\n!s1a2 = Omniverse\n!s1a3 = Broken Symmetry\n!s1a4 = Extropy\n!s1a5 = Defiant\n!s1a6 = Spectacle\n!s1a7 = Syllablke Theory\n!s1a8 = The Grand Cypher \n!s1a9 = Many Worlds\n!s1a10 = Omnithoughts\n!s1a11 = 5th\n!s1a12 = 2016 Athiest Dreadnought\n!s1a13 = Second World Cab Ride\n!s1a14 = .8\n!s1a15 = Another Lens\n!s1a16 = Bad Plan\n!s1a17 = Frame of Referance \n!s1a18 = Greyshift\n!s1a19 = Society Versus Nature\n!s1a20 = Ambush Situation\n!s1a21 = Landscape\n!s1a22 = Beachfront\n!s1a23 = Interdimensional Council of Greys\n!s1a24 = Guardians of Knowleadge\n!s1a25 = Dreams of the Dreamer\n!s1a26 = The Master Paradox\n!s1a27 = Star Breaker\n!s1a28 = Bizzarchitecture\n!s1a29 = Infinitease\n!s1a30 = Far Beyond The Bars") 
		return
		
	async def cmd_s1b(self, channel):
		await self.safe_send_message(channel,
		"You selected Type II : The Mandelbrot Set by Greydon Square"\
		"\nPlease select a song:"\
		"\n!s1b1 = Galaxy Rise"\
		"\n!s1b2 = 4th"\
		"\n!s1b3 = Snowflakes and Flowsnakes"\
		"\n!s1b4 = Peace Peace"\
		"\n!s1b5 = Flower Girl"\
		"\n!s1b6 = 2013 Athiest Dreadnought"\
		"\n!s1b7 = Grow Too Old Soon"\
		"\n!s1b8 = Prison Planet"\
		"\n!s1b9 = Interstellar"\
		"\n!s1b10 = 1-2, 1-2"\
		"\n!s1b11 = Dopamine Notes"\
		"\n!s1b12 = Judgement Day"\
		"\n!s1b13 = Rhyme Sickness from Orion Cygnus"\
		"\n!s1b14 = Metaphor Swordsman"\
		"\n!s1b15 = 6 Blankas(feat. C Gats & Canibus)"\
		"\n!s1b16 = Borrowed Time"\
		"\n!s1b17 = #GU After-Party (feat. DJ Zashone)"\
		"\n!s1b18 = Ultra Combo"\
		"\n!s1b19 = Summer's Ending"\
		"\n!s1b20 = .7"\
		"\n!s1b21 = As a Legend"\
		"\n!s1b22 = Final Kata"\
		)
		return
		
	async def cmd_s1c(self, channel):
		await self.safe_send_message(channel,
		"You selected Type I : The Kardashev Scale by Greydon Square"\
		"\nPlease select a song:"\
		"\n!s1c1 = Star View"\
		"\n!s1c2 = War Porn(feat. Canabis)"\
		"\n!s1c3 = Onward"\
		"\n!s1c4 = The Kardashev Scale"\
		"\n!s1c5 = Speak To Him(feat. Gripp)"\
		"\n!s1c6 = Brains"\
		"\n!s1c7 = Myth"\
		"\n!s1c8 = 2010 A.D. (feat. Syqnys & TaskRok)"\
		"\n!s1c9 = Here's why I don't believe..."\
		"\n!s1c10 = Man-Made God"\
		"\n!s1c11 = Proof of Concept"\
		"\n!s1c12 = Stockholm Syndrome"\
		"\n!s1c13 = Stockholm Syndrome"\
		"\n!s1c14 = Special Pleading"\
		"\n!s1c15 = World Around Us"\
		"\n!s1c16 = As an artist"\
		"\n!s1c17 = Final Notes"\
		"\n!s1c18 = A.I.M (Anti-Injustice Music)"\
		"\n!s1c19 = Dopamine Kata")
		return	
	
	

	
	async def cmd_s1a1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/cosmic-harvest")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/omniverse")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/broken-symmetry-feat-tombstone-da-deadman")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/extropy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/defiant")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/spectacle")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/syllable-theory")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/the-grand-cypher-feat-johnny-hoax-indefinite-mc-brooks-lioness-saxa-c-gats-eville-as-grand-unified")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/many-worlds")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a10(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/omnithoughts")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a11(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/5th")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a12(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/2016-atheist-dreadnought-feat-tombstone-da-deadman-c-gats-johnny-hoax-syqnys-as-grand-unified")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a13(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/second-world-cab-ride")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a14(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/8")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a15(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/another-lens")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a16(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/bad-plan")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a17(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/frame-of-reference")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a18(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/greyshift")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a19(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/society-versus-nature")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a20(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/ambush-situation-feat-blue-picaso")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a21(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/landscape")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a22(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/beachfront")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a23(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/interdimensional-council-of-greys")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a24(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/guardians-of-knowledge-feat-syqnys-johnny-hoax")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a25(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/dreams-of-the-dreamer")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a26(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/the-master-paradox-as-a-master")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a27(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/star-breaker")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a28(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/bizzarchitecture")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1a29(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/infinitease")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
	async def cmd_s1a30(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/far-beyond-the-bars")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	
	
	
	
	
	
	
	
	async def cmd_s1b1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/galaxy-rise")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/4th")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/snowflakes-and-flowsnakes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/peace-peace")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/flower-girl")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/2013-atheist-dreadnought-lady-assassin-syqnys-greydon-square-tombstone-da-deadman-johnny-hoax-gripp-task-rok")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/grow-too-old-soon")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/prison-planet")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/interstellar")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b10(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/1-21-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b11(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/dopamine-notes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b12(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/judgement-day")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b13(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/rhyme-sickness-from-orion-cygnus")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b14(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/metaphor-swordsman")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b15(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/6-blankas-feat-c-gats-canibus")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b16(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/borrowed-time")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b17(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/gu-after-party-feat-dj-zashone")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b18(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/ultra-combo")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b19(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/ultra-combo")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b20(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/7")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b21(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/as-a-legend")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1b22(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/final-kata")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
		
		
		
		
	
	async def cmd_s1c1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/star-view")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/war-porn-feat-canibus")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/onward")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/the-kardashev-scale")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/speak-to-him-feat-gripp")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/brains")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/myth")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/2010-a-d-feat-syqnys-taskrok")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/heres-why-i-dont-believe")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c10(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/man-made-god")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c11(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/proof-of-concept")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c12(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/stockholm-syndrome")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c13(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/black-atheist-feat-noob-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c14(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/special-pleading")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c15(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/world-around-us")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c16(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/as-an-artist")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c17(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/final-notes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c18(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/a-i-m-anti-injustice-music")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s1c19(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://greydonsquare.bandcamp.com/track/dopamine-kata")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		

	async def cmd_s1d1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/the-cpt-theorem")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/cubed")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/2008-a-d-feat-jayez-dallas-taskrok-mr-gawn-syqnys")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/judge-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/mission-statement")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/game-genie")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/fun-games")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/group-home-kid")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/a-soldiers-poem")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/broken-home")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/so-what")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/n-word")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/ascension")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/galactica-actual")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/say-15")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1d16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/159-bars-bonus")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s1d(self, channel):
		await self.safe_send_message(channel,
		"You selected: The Cpt Theorem"\
		"\nPlease select a song:"\
		"\n!s1d1 = the cpt theorem"\
		"\n!s1d2 = cubed"\
		"\n!s1d3 = 2008 a d feat jayez dallas taskrok mr gawn syqnys"\
		"\n!s1d4 = judge me"\
		"\n!s1d5 = mission statement"\
		"\n!s1d6 = game genie"\
		"\n!s1d7 = fun games"\
		"\n!s1d8 = group home kid"\
		"\n!s1d9 = a soldiers poem"\
		"\n!s1d10 = broken home"\
		"\n!s1d11 = so what"\
		"\n!s1d12 = n word"\
		"\n!s1d13 = ascension"\
		"\n!s1d14 = galactica actual"\
		"\n!s1d15 = say 15"\
		"\n!s1d16 = 159 bars bonus")

	async def cmd_s1e1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/a-rational-response")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/the-compton-effect")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/molotov")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/extian")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/buddy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/psych-eval")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/roots")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/pandoras-box")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/ears")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/stranger-feat-traumah")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/squared")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/say")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/addressed")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/the-dream")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/gone")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/dear-journal")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s1e17(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://greydonsquare.bandcamp.com/track/as-a-fan")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
	async def cmd_s1e(self, channel):
		await self.safe_send_message(channel,
		"You selected: The Compton Effect"\
		"\nPlease select a song:"\
		"\n!s1e1 = a rational response"\
		"\n!s1e2 = the compton effect"\
		"\n!s1e3 = molotov"\
		"\n!s1e4 = extian"\
		"\n!s1e5 = buddy"\
		"\n!s1e6 = psych eval"\
		"\n!s1e7 = roots"\
		"\n!s1e8 = pandoras box"\
		"\n!s1e9 = ears"\
		"\n!s1e10 = stranger feat traumah"\
		"\n!s1e11 = squared"\
		"\n!s1e12 = say"\
		"\n!s1e13 = addressed"\
		"\n!s1e14 = the dream"\
		"\n!s1e15 = gone"\
		"\n!s1e16 = dear journal"\
		"\n!s1e17 = as a fan")


		
		
		
	
	async def cmd_s2a1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/information-audio")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/sisters-brothers")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/4-minutes-20-seconds-feat-low-technology")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/spend-a-lot-of-time")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/police-thiefs")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/caught-up")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/lies")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/take-advantage")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/sometimes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a10(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"hhttps://informationmusic.bandcamp.com/track/smiling-faces")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a11(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/do-what-you-want")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a12(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/watch-where-i-go")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s2a13(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://informationmusic.bandcamp.com/track/misunderstood-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
		
		
	async def cmd_s3a1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://www.youtube.com/watch?v=frQd-Hzm_c4")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s3a2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://www.youtube.com/watch?v=d6nTdYQZvh0")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
	
	async def cmd_s4b(self, channel):
		await self.safe_send_message(channel,"You selected The 6th Extinction\nPlease select a song:\n!s4b1 = The 6th Extinction\n!s4b2 = No More Messiahs\n!s4b3 = Legacy\n!s4b4 = Anti-Hero\n!s4b5 = On My Own\n!s4b6 = Necessary Evil\n!s4b7 = When Worlds Collide Feat Greydon Square\n!s4b8 = Keep It Moving")
		return
		
	async def cmd_s4a(self, channel):
		await self.safe_send_message(channel,"You selected Rise of The Reapers\nPlease select a song:\n!s4a1 = Intro(Reaper Rally)\n!s1a2 = Ruthless Aggression\n!s4a3 = Rise of the Reapers\n!s1a4 = Vintage\n!s4a5 = War For The Minds\n!s1a6 = All Fall Down\n!s4a7 = Monster\n!s1a8 = Bloodsport Feat Greydon Square\n!s4a9 = Descent Into Madness") 
		return
		
	async def cmd_s4a1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/intro-reaper-rally")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/ruthless-aggression")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/rise-of-the-reapers")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/vintage")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/all-fall-down")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/all-fall-down")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/monster")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/monster")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4a9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/descent-into-madness-feat-napalm-hyru")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
		
	
	
	async def cmd_s4b1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/the-6th-extinction")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/no-more-messiahs-feat-napalm-hyru")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/legacy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/anti-hero")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/on-my-own")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/necessary-evil-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b7(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/when-worlds-collide-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s4b8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://tombstonedadeadman.bandcamp.com/track/keep-it-moving-feat-napalm-hyru-adekwit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	

	
	async def cmd_s5a(self, channel):
		await self.safe_send_message(channel,
			"You selected VI. Syqs\nPlease select a song:\n!s5a1 = Life Is But A Play\n!s5a2 = Trigger Warning (Skit)\n!s5a3 = Age Of Outrage (feat. Greydon Square)\n!s5a4 = Jesus Is The Only Way\n!s5a5 = Dumb\n!s5a6 = Message From Reality (Skit)\n!s5a7 = Beautiful Musical\n!s5a8 = Paradox Place\n!s5a9 = Come With Me\n!s5a10 = My First Selfie (Skit)\n!s5a11 = Alien\n!s5a12 = Scotch And Red Wine\n!s5a13 = Nate Diaz\n!s5a14 = Cheating Fans (Skit)\n!s5a15 = Laughing\n!s5a16 = Dark Clouds\n!s5a17 = My Computer\n!s5a18 = Fire (feat. Talon)\n!s5a19 = Keirkegaard's Train\n!s1a20 = Damn It-Outro")
		return
	
	
	async def cmd_s5a1(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/life-is-but-a-play")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a2(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/trigger-warning-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a3(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/age-of-outrage-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a4(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/jesus-is-the-only-way")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a5(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/dumb")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a6(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/message-from-reality-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a7(self, player ,channel, author, permissions, leftover_args):

		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/message-from-reality-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a8(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/paradox-place")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a9(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/come-with-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a10(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/my-first-selfie-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a11(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/alien-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a12(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/scotch-and-red-wine-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a13(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/nate-diaz")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a14(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/cheating-fans-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a15(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/laughing")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a16(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/dark-clouds")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a17(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/my-computer")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a18(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/fire-feat-talon")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a19(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/kierkegaards-train")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5a20(self, player ,channel, author, permissions, leftover_args):
	
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
			"https://syqs.bandcamp.com/track/damn-it-outro")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	

	async def cmd_s5b1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/the-nausea")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/evil-atheist")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/magic-curtain")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hashtag-genocide-feat-baba-brinkman")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/a-dreadful-engagement")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hurt-me-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/the-raven")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/jaded-eyes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/know-when-to-hold-em")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/astronomer")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/fee-fi-fo-fum")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/muhammad-ali-feat-kritizizm")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/worms")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/mediocre-mortal-melancholy-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5b15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/lost-in-the-spotlight-feat-chy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s5b(self, channel):
		await self.safe_send_message(channel,
		"You selected: IV. The Nausea"\
		"\nPlease select a song:"\
		"\n!s5b1 = the nausea"\
		"\n!s5b2 = evil atheist"\
		"\n!s5b3 = magic curtain"\
		"\n!s5b4 = hashtag genocide feat baba brinkman"\
		"\n!s5b5 = a dreadful engagement"\
		"\n!s5b6 = hurt me feat greydon square"\
		"\n!s5b7 = the raven"\
		"\n!s5b8 = jaded eyes"\
		"\n!s5b9 = know when to hold em"\
		"\n!s5b10 = astronomer"\
		"\n!s5b11 = fee fi fo fum"\
		"\n!s5b12 = muhammad ali feat kritizizm"\
		"\n!s5b13 = worms"\
		"\n!s5b14 = mediocre mortal melancholy me"\
		"\n!s5b15 = lost in the spotlight feat chy")

	async def cmd_s5c1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/41-feat-chy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/chasing-the-rabbit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/cartoon-colored-nightmares")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/cos-mic-feat-johnny-hoax-rion-atom-tac-and-c-gats")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/2015")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/narcyssyst")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/fuq-the-world")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/happy-animeal")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/its-all-a-conspiracy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/dsdg-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/spark-feat-ogma")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/wreck-it-ralph-feat-honu-and-my-kids")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5c13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/no-regrets")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s5c(self, channel):
		await self.safe_send_message(channel,
		"You selected: V. Chasing the Rabbit"\
		"\nPlease select a song:"\
		"\n!s5c1 = 41 feat chy"\
		"\n!s5c2 = chasing the rabbit"\
		"\n!s5c3 = cartoon colored nightmares"\
		"\n!s5c4 = cos mic feat johnny hoax rion atom tac and c gats"\
		"\n!s5c5 = 2015"\
		"\n!s5c6 = narcyssyst"\
		"\n!s5c7 = fuq the world"\
		"\n!s5c8 = happy animeal"\
		"\n!s5c9 = its all a conspiracy"\
		"\n!s5c10 = dsdg feat greydon square"\
		"\n!s5c11 = spark feat ogma"\
		"\n!s5c12 = wreck it ralph feat honu and my kids"\
		"\n!s5c13 = no regrets")

	async def cmd_s5d1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hypatias-reign-feat-chy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/syqo")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/human-being")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hurt-you-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/monster")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/im-syq-part-two")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/butterfly")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/ballet")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/science-is-music")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/fantasy-feat-kritizizm")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/paintbrush")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/poison")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/heaven-and-hell")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/miss-fame-miss")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/so-long-feat-talon")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/rain-feat-chy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5d17(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hypatia-rain")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s5d(self, channel):
		await self.safe_send_message(channel,
		"You selected: III. Hypatia's Reign"\
		"\nPlease select a song:"\
		"\n!s5d1 = hypatias reign feat chy"\
		"\n!s5d2 = syqo"\
		"\n!s5d3 = human being"\
		"\n!s5d4 = hurt you feat greydon square"\
		"\n!s5d5 = monster"\
		"\n!s5d6 = im syq part two"\
		"\n!s5d7 = butterfly"\
		"\n!s5d8 = ballet"\
		"\n!s5d9 = science is music"\
		"\n!s5d10 = fantasy feat kritizizm"\
		"\n!s5d11 = paintbrush"\
		"\n!s5d12 = poison"\
		"\n!s5d13 = heaven and hell"\
		"\n!s5d14 = miss fame miss"\
		"\n!s5d15 = so long feat talon"\
		"\n!s5d16 = rain feat chy"\
		"\n!s5d17 = hypatia rain")

	async def cmd_s5e1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/blasphemy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/evil-robots-and-flying-cars")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/the-sky-is-falling")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/fuq-shyt-up-feat-pakman")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/s-t-s-h-n-b-m-skit")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/handi-rap")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/i-am-human")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/jesus-piece")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/candy-rap")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/boom-goes-the-dynamite")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/fairytales")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/sexytime")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/ann-hannity-and-rush-oreilly")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hard-head")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/l8-again")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/rational-response-squad")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e17(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/hush-your-breath")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s5e18(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://syqs.bandcamp.com/track/dreams-and-nightmares")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)
	
	async def cmd_s5e(self, channel):
		await self.safe_send_message(channel,
		"You selected: II. CandyCap Rap and the L8Gr8 Atheist: Why Syqnys is the Future of Rap and Starving Children Taste Good"\
		"\nPlease select a song:"\
		"\n!s5e1 = blasphemy"\
		"\n!s5e2 = evil robots and flying cars"\
		"\n!s5e3 = the sky is falling"\
		"\n!s5e4 = fuq shyt up feat pakman"\
		"\n!s5e5 = s t s h n b m skit"\
		"\n!s5e6 = handi rap"\
		"\n!s5e7 = i am human"\
		"\n!s5e8 = jesus piece"\
		"\n!s5e9 = candy rap"\
		"\n!s5e10 = boom goes the dynamite"\
		"\n!s5e11 = fairytales"\
		"\n!s5e12 = sexytime"\
		"\n!s5e13 = ann hannity and rush oreilly"\
		"\n!s5e14 = hard head"\
		"\n!s5e15 = l8 again"\
		"\n!s5e16 = rational response squad"\
		"\n!s5e17 = hush your breath"\
		"\n!s5e18 = dreams and nightmares")
	
	async def cmd_s6a1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/chocolate")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6a2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/joy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6a3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/day-in-the-life")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6a4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/addicted-to-acknowledgement")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6a5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/speak-for-yourself")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s6a(self, channel):
		await self.safe_send_message(channel,
		"You selected: Prelude to Perfection"\
		"\nPlease select a song:"\
		"\n!s6a1 = chocolate"\
		"\n!s6a2 = joy"\
		"\n!s6a3 = day in the life"\
		"\n!s6a4 = addicted to acknowledgement"\
		"\n!s6a5 = speak for yourself")

	async def cmd_s6b1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/type-invincible-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/og")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/finest-features")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/day-1")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/loneliness")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/talking-to-myself")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/walking")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/together")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/have-a-heart")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6b10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/paradise")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s6b(self, channel):
		await self.safe_send_message(channel,
		"You selected: Talking to Myself"\
		"\nPlease select a song:"\
		"\n!s6b1 = type invincible 2"\
		"\n!s6b2 = og"\
		"\n!s6b3 = finest features"\
		"\n!s6b4 = day 1"\
		"\n!s6b5 = loneliness"\
		"\n!s6b6 = talking to myself"\
		"\n!s6b7 = walking"\
		"\n!s6b8 = together"\
		"\n!s6b9 = have a heart"\
		"\n!s6b10 = paradise")

	async def cmd_s6c1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/gentlemens-agreement")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/tell-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/thought-i-knew")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/nothing-lasts-forever")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/high-road-hopes")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/conceding-my-profits")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/masterpiece-theater")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/hear-you-talking")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/check-check")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/nobody-cares")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6c11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/excuses")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s6c(self, channel):
		await self.safe_send_message(channel,
		"You selected: Nothing Lasts Forever"\
		"\nPlease select a song:"\
		"\n!s6c1 = gentlemens agreement"\
		"\n!s6c2 = tell me"\
		"\n!s6c3 = thought i knew"\
		"\n!s6c4 = nothing lasts forever"\
		"\n!s6c5 = high road hopes"\
		"\n!s6c6 = conceding my profits"\
		"\n!s6c7 = masterpiece theater"\
		"\n!s6c8 = hear you talking"\
		"\n!s6c9 = check check"\
		"\n!s6c10 = nobody cares"\
		"\n!s6c11 = excuses")

	async def cmd_s6d1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/easy-to-find")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/message-that-youre-missing")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/rest-of-your-life")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/has-been-status")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/stick-em-up")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/surrender")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/professional-courtesy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/wonderful")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/just-like-this")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/take-me-to-the-future")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/lengthen-the-lifespan")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6d12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/cloudy-and-grey")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s6d(self, channel):
		await self.safe_send_message(channel,
		"You selected: Lengthen the Lifespan"\
		"\nPlease select a song:"\
		"\n!s6d1 = easy to find"\
		"\n!s6d2 = message that youre missing"\
		"\n!s6d3 = rest of your life"\
		"\n!s6d4 = has been status"\
		"\n!s6d5 = stick em up"\
		"\n!s6d6 = surrender"\
		"\n!s6d7 = professional courtesy"\
		"\n!s6d8 = wonderful"\
		"\n!s6d9 = just like this"\
		"\n!s6d10 = take me to the future"\
		"\n!s6d11 = lengthen the lifespan"\
		"\n!s6d12 = cloudy and grey")

	async def cmd_s6e1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/save-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/fresh-to-death")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/feed-your-fix")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/excuse-me")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/the-message")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/two-weeks-notice")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/what-we-want")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/you-always-knew-it")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/walk-with-us")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/gold-chains-gunfights-and-tattoos")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/loudest-of-guns-bonus-track")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/no-chance-to-escape-bonus-track")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s6e13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://spanphly.bandcamp.com/track/two-years-later-bonus-track")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s6e(self, channel):
		await self.safe_send_message(channel,
		"You selected: Two Weeks Notice: Deluxe Edition"\
		"\nPlease select a song:"\
		"\n!s6e1 = save me"\
		"\n!s6e2 = fresh to death"\
		"\n!s6e3 = feed your fix"\
		"\n!s6e4 = excuse me"\
		"\n!s6e5 = the message"\
		"\n!s6e6 = two weeks notice"\
		"\n!s6e7 = what we want"\
		"\n!s6e8 = you always knew it"\
		"\n!s6e9 = walk with us"\
		"\n!s6e10 = gold chains gunfights and tattoos"\
		"\n!s6e11 = loudest of guns bonus track"\
		"\n!s6e12 = no chance to escape bonus track"\
		"\n!s6e13 = two years later bonus track")


	
	
	async def cmd_s7a1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/attack-on-titan")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/gatzilla-track-killaz")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/soul")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/remember")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/zillalude-1")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/b-i-t-n-b-blue-is-the-new-black")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/stop")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/drone-cypher-feat-greydon-square")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/zillalude-2")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/wheres-the-change")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/weirdos-feat-eville")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7a12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/push-feat-gifted-anomaly-tombstone-da-deadman-charlie-rose")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s7a(self, channel):
		await self.safe_send_message(channel,
		"You selected: GatZilla (C​-​Gats & Zpu​-​Zilla) - Attack on Titan"\
		"\nPlease select a song:"\
		"\n!s7a1 = attack on titan"\
		"\n!s7a2 = gatzilla track killaz"\
		"\n!s7a3 = soul"\
		"\n!s7a4 = remember"\
		"\n!s7a5 = zillalude 1"\
		"\n!s7a6 = b i t n b blue is the new black"\
		"\n!s7a7 = stop"\
		"\n!s7a8 = drone cypher feat greydon square"\
		"\n!s7a9 = zillalude 2"\
		"\n!s7a10 = wheres the change"\
		"\n!s7a11 = weirdos feat eville"\
		"\n!s7a12 = push feat gifted anomaly tombstone da deadman charlie rose")

	async def cmd_s7b1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/the-real")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/absolute")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/back-to-you-ft-dj-mr-phantastik")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/graffiti")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/devil")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/speed-racin-unfinished")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/genius-ft-eville-agg")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/sooner-or-later-ft-eville")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7b9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/you-cant-produced-by-rare-kommodity")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s7b(self, channel):
		await self.safe_send_message(channel,
		'You selected: C Gats & Charlie Rose - "Something Time Forgot: The Lost Mixtape"'\
		"\nPlease select a song:"\
		"\n!s7b1 = the real"\
		"\n!s7b2 = absolute"\
		"\n!s7b3 = back to you ft dj mr phantastik"\
		"\n!s7b4 = graffiti"\
		"\n!s7b5 = devil"\
		"\n!s7b6 = speed racin unfinished"\
		"\n!s7b7 = genius ft eville agg"\
		"\n!s7b8 = sooner or later ft eville"\
		"\n!s7b9 = you cant produced by rare kommodity")

	async def cmd_s7c1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/1-p-p-2-intro")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/2-last-rites-ft-eville")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/3-absolute-ft-charlie-rose")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/4-good-night")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/5-coroners-report-ft-cb-wonder")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/6-therapeutic-music")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/7-c-gats-run-it")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/8-a-1-ominous-flow")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/9-crime-of-passion-produced-by-bruce-williams")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/10-loyalty-honor-respect-ft-eville-greydon-square-produced-by-rare-kommodity")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/1180s-baby-ft-agg-produced-by-classik-beatz")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/12-definition-free-mix-ft-phant")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/13-wandas-song")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/14-keepsake-produced-by-zpu-zilla")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/15-friend-zone-ft-lady-assasin")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7c16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/17-fistful-of-scholars-ft-charlie-rose-cb-wonder-eville-agg-kay-m")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s7c(self, channel):
		await self.safe_send_message(channel,
		"You selected: Passion & Progress Vol. 2: Therapeutic Music"\
		"\nPlease select a song:"\
		"\n!s7c1 = 1 p p 2 intro"\
		"\n!s7c2 = 2 last rites ft eville"\
		"\n!s7c3 = 3 absolute ft charlie rose"\
		"\n!s7c4 = 4 good night"\
		"\n!s7c5 = 5 coroners report ft cb wonder"\
		"\n!s7c6 = 6 therapeutic music"\
		"\n!s7c7 = 7 c gats run it"\
		"\n!s7c8 = 8 a 1 ominous flow"\
		"\n!s7c9 = 9 crime of passion produced by bruce williams"\
		"\n!s7c10 = 10 loyalty honor respect ft eville greydon square produced by rare kommodity"\
		"\n!s7c11 = 1180s baby ft agg produced by classik beatz"\
		"\n!s7c12 = 12 definition free mix ft phant"\
		"\n!s7c13 = 13 wandas song"\
		"\n!s7c14 = 14 keepsake produced by zpu zilla"\
		"\n!s7c15 = 15 friend zone ft lady assasin"\
		"\n!s7c16 = 17 fistful of scholars ft charlie rose cb wonder eville agg kay m")

	async def cmd_s7d1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/say-whats-real-freestyle-intro")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/reelmatic-an-ode-to-illmatic-part-i")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/im-back-ft-ill-answer-produced-by-rare-kommodity")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/king-flow")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/baboon-rap-ft-eville")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/genesis-freestyle")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/state-of-grace-freestyle")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/future-freestyle-million-dollar-idea-ft-charlie-rose")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/put-it-in-the-air-freestyle")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/exhibit-dmv-ft-eville-agg-so-authentic")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/say-somethin-freestyle")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/that-shhh-produced-by-rare-kommodity")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/black-belt-theatre-produced-by-classikbeatz")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/so-wu-wu-tang-homage")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/inkomparable-ft-eville")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s7d16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://cgats.bandcamp.com/track/fertile-ground-ft-eville-agg-so-authentic")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s7d(self, channel):
		await self.safe_send_message(channel,
		"You selected: Passion & Progress Vol. 1"\
		"\nPlease select a song:"\
		"\n!s7d1 = say whats real freestyle intro"\
		"\n!s7d2 = reelmatic an ode to illmatic part i"\
		"\n!s7d3 = im back ft ill answer produced by rare kommodity"\
		"\n!s7d4 = king flow"\
		"\n!s7d5 = baboon rap ft eville"\
		"\n!s7d6 = genesis freestyle"\
		"\n!s7d7 = state of grace freestyle"\
		"\n!s7d8 = future freestyle million dollar idea ft charlie rose"\
		"\n!s7d9 = put it in the air freestyle"\
		"\n!s7d10 = exhibit dmv ft eville agg so authentic"\
		"\n!s7d11 = say somethin freestyle"\
		"\n!s7d12 = that shhh produced by rare kommodity"\
		"\n!s7d13 = black belt theatre produced by classikbeatz"\
		"\n!s7d14 = so wu wu tang homage"\
		"\n!s7d15 = inkomparable ft eville"\
		"\n!s7d16 = fertile ground ft eville agg so authentic")
	
	
	
	
	async def cmd_s8a(self, channel):
		await self.safe_send_message(channel,
		"You selected: No Gods No Kings Only Timelords"\
		"\nPlease select a song:"\
		"\n!s8a1 = intro to alchemy"\
		"\n!s8a2 = ngnkot"\
		"\n!s8a3 = class of 92 i am theta sigma"\
		"\n!s8a4 = north by northeast"\
		"\n!s8a5 = melodic ministry"\
		"\n!s8a6 = next stop type 4"\
		"\n!s8a7 = interlude 416"\
		"\n!s8a8 = under the starry skies"\
		"\n!s8a9 = stay woke"\
		"\n!s8a10 = straight outta kastaborous"\
		"\n!s8a11 = the music in you interlude"\
		"\n!s8a12 = 12th revisits the sunmakers"\
		"\n!s8a13 = the jam at cern interlude"\
		"\n!s8a14 = delusions and illusions"\
		"\n!s8a15 = jungle juice"\
		"\n!s8a16 = they love the loot"\
		"\n!s8a17 = return of the last starfighter"\
		"\n!s8a18 = stuck on staccato"\
		"\n!s8a19 = in so many words outro")

	
	

	async def cmd_s8a1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/intro-to-alchemy")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/ngnkot")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/class-of-92-i-am-theta-sigma")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/north-by-northeast")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/melodic-ministry")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/next-stop-type-4")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/interlude-416")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/under-the-starry-skies")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/stay-woke")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/straight-outta-kastaborous")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/the-music-in-you-interlude")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/12th-revisits-the-sunmakers")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/the-jam-at-cern-interlude")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/delusions-and-illusions")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a15(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/jungle-juice")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a16(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/they-love-the-loot")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a17(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/return-of-the-last-starfighter")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a18(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/stuck-on-staccato")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s8a19(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://thetwelfthdoctor.bandcamp.com/track/in-so-many-words-outro")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)



	async def cmd_s9a1(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/fearless")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a2(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/revenge-of-the-nerds")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a3(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/oranges")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a4(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/sandmen")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a5(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/havoc-protocol")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a6(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/mazed-awakening")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a7(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/synopsis")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a8(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/there")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a9(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/tone-deaf")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a10(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/major-phi")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a11(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/late-night-munchies")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a12(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/the-spliffhanger")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a13(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/lt-x-poa-feat-the-progeny-of-ancients")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)

	async def cmd_s9a14(self, player ,channel, author, permissions, leftover_args):
		await self.cmd_play( player, channel, author, permissions, leftover_args, 
		"https://lowtechnology.bandcamp.com/track/flagship-feat-kizzle-the-emcee")
		await self.post_lastinqueue( player ,channel, author, permissions, leftover_args)


	async def cmd_s9(self, channel):
		await self.safe_send_message(channel,
		"You selected: LTGU"\
		"\nPlease select a song:"\
		"\n!s9a1 = fearless"\
		"\n!s9a2 = revenge of the nerds"\
		"\n!s9a3 = oranges"\
		"\n!s9a4 = sandmen"\
		"\n!s9a5 = havoc protocol"\
		"\n!s9a6 = mazed awakening"\
		"\n!s9a7 = synopsis"\
		"\n!s9a8 = there"\
		"\n!s9a9 = tone deaf"\
		"\n!s9a10 = major phi"\
		"\n!s9a11 = late night munchies"\
		"\n!s9a12 = the spliffhanger"\
		"\n!s9a13 = lt x poa feat the progeny of ancients"\
		"\n!s9a14 = flagship feat kizzle the emcee")



    
    
    
    
    
    
    
    
    
    
    
    
    
    async def cmd_id(self, author, user_mentions):
        """
        Usage:
            {command_prefix}id [@user]

        Tells the user their id or the id of another user.
        """
        if not user_mentions:
            return Response('your id is `%s`' % author.id, reply=True, delete_after=35)
        else:
            usr = user_mentions[0]
            return Response("%s's id is `%s`" % (usr.name, usr.id), reply=True, delete_after=35)

    @owner_only
    async def cmd_joinserver(self, message, server_link=None):
        """
        Usage:
            {command_prefix}joinserver invite_link

        Asks the bot to join a server.  Note: Bot accounts cannot use invite links.
        """

        if self.user.bot:
            url = await self.generate_invite_link()
            return Response(
                "Bot accounts can't use invite links!  Click here to add me to a server: \n{}".format(url),
                reply=True, delete_after=30
            )

        try:
            if server_link:
                await self.accept_invite(server_link)
                return Response("\N{THUMBS UP SIGN}")

        except:
            raise exceptions.CommandError('Invalid URL provided:\n{}\n'.format(server_link), expire_in=30)

    async def cmd_play(self, player, channel, author, permissions, leftover_args, song_url):
        """
        Usage:
            {command_prefix}play song_link
            {command_prefix}play text to search for

        Adds the song to the playlist.  If a link is not provided, the first
        result from a youtube search is added to the queue.
        """

        song_url = song_url.strip('<>')

        if permissions.max_songs and player.playlist.count_for_user(author) >= permissions.max_songs:
            raise exceptions.PermissionsError(
                "You have reached your enqueued song limit (%s)" % permissions.max_songs, expire_in=30
            )

        await self.send_typing(channel)

        if leftover_args:
            song_url = ' '.join([song_url, *leftover_args])

        try:
            info = await self.downloader.extract_info(player.playlist.loop, song_url, download=False, process=False)
        except Exception as e:
            raise exceptions.CommandError(e, expire_in=30)

        if not info:
            raise exceptions.CommandError(
                "That video cannot be played.  Try using the {}stream command.".format(self.config.command_prefix),
                expire_in=30
            )

        # abstract the search handling away from the user
        # our ytdl options allow us to use search strings as input urls
        if info.get('url', '').startswith('ytsearch'):
            # print("[Command:play] Searching for \"%s\"" % song_url)
            info = await self.downloader.extract_info(
                player.playlist.loop,
                song_url,
                download=False,
                process=True,    # ASYNC LAMBDAS WHEN
                on_error=lambda e: asyncio.ensure_future(
                    self.safe_send_message(channel, "```\n%s\n```" % e, expire_in=120), loop=self.loop),
                retry_on_error=True
            )

            if not info:
                raise exceptions.CommandError(
                    "Error extracting info from search string, youtubedl returned no data.  "
                    "You may need to restart the bot if this continues to happen.", expire_in=30
                )

            if not all(info.get('entries', [])):
                # empty list, no data
                log.debug("Got empty list, no data")
                return

            # TODO: handle 'webpage_url' being 'ytsearch:...' or extractor type
            song_url = info['entries'][0]['webpage_url']
            info = await self.downloader.extract_info(player.playlist.loop, song_url, download=False, process=False)
            # Now I could just do: return await self.cmd_play(player, channel, author, song_url)
            # But this is probably fine

        # TODO: Possibly add another check here to see about things like the bandcamp issue
        # TODO: Where ytdl gets the generic extractor version with no processing, but finds two different urls

        if 'entries' in info:
            # I have to do exe extra checks anyways because you can request an arbitrary number of search results
            if not permissions.allow_playlists and ':search' in info['extractor'] and len(info['entries']) > 1:
                raise exceptions.PermissionsError("You are not allowed to request playlists", expire_in=30)

            # The only reason we would use this over `len(info['entries'])` is if we add `if _` to this one
            num_songs = sum(1 for _ in info['entries'])

            if permissions.max_playlist_length and num_songs > permissions.max_playlist_length:
                raise exceptions.PermissionsError(
                    "Playlist has too many entries (%s > %s)" % (num_songs, permissions.max_playlist_length),
                    expire_in=30
                )

            # This is a little bit weird when it says (x + 0 > y), I might add the other check back in
            if permissions.max_songs and player.playlist.count_for_user(author) + num_songs > permissions.max_songs:
                raise exceptions.PermissionsError(
                    "Playlist entries + your already queued songs reached limit (%s + %s > %s)" % (
                        num_songs, player.playlist.count_for_user(author), permissions.max_songs),
                    expire_in=30
                )

            if info['extractor'].lower() in ['youtube:playlist', 'soundcloud:set', 'bandcamp:album']:
                try:
                    return await self._cmd_play_playlist_async(player, channel, author, permissions, song_url, info['extractor'])
                except exceptions.CommandError:
                    raise
                except Exception as e:
                    log.error("Error queuing playlist", exc_info=True)
                    raise exceptions.CommandError("Error queuing playlist:\n%s" % e, expire_in=30)

            t0 = time.time()

            # My test was 1.2 seconds per song, but we maybe should fudge it a bit, unless we can
            # monitor it and edit the message with the estimated time, but that's some ADVANCED SHIT
            # I don't think we can hook into it anyways, so this will have to do.
            # It would probably be a thread to check a few playlists and get the speed from that
            # Different playlists might download at different speeds though
            wait_per_song = 1.2

            procmesg = await self.safe_send_message(
                channel,
                'Gathering playlist information for {} songs{}'.format(
                    num_songs,
                    ', ETA: {} seconds'.format(fixg(
                        num_songs * wait_per_song)) if num_songs >= 10 else '.'))

            # We don't have a pretty way of doing this yet.  We need either a loop
            # that sends these every 10 seconds or a nice context manager.
            await self.send_typing(channel)

            # TODO: I can create an event emitter object instead, add event functions, and every play list might be asyncified
            #       Also have a "verify_entry" hook with the entry as an arg and returns the entry if its ok

            entry_list, position = await player.playlist.import_from(song_url, channel=channel, author=author)

            tnow = time.time()
            ttime = tnow - t0
            listlen = len(entry_list)
            drop_count = 0

            if permissions.max_song_length:
                for e in entry_list.copy():
                    if e.duration > permissions.max_song_length:
                        player.playlist.entries.remove(e)
                        entry_list.remove(e)
                        drop_count += 1
                        # Im pretty sure there's no situation where this would ever break
                        # Unless the first entry starts being played, which would make this a race condition
                if drop_count:
                    print("Dropped %s songs" % drop_count)

            log.info("Processed {} songs in {} seconds at {:.2f}s/song, {:+.2g}/song from expected ({}s)".format(
                listlen,
                fixg(ttime),
                ttime / listlen if listlen else 0,
                ttime / listlen - wait_per_song if listlen - wait_per_song else 0,
                fixg(wait_per_song * num_songs))
            )

            await self.safe_delete_message(procmesg)

            if not listlen - drop_count:
                raise exceptions.CommandError(
                    "No songs were added, all songs were over max duration (%ss)" % permissions.max_song_length,
                    expire_in=30
                )

            reply_text = "Enqueued **%s** songs to be played. Position in queue: %s"
            btext = str(listlen - drop_count)

        else:
            if permissions.max_song_length and info.get('duration', 0) > permissions.max_song_length:
                raise exceptions.PermissionsError(
                    "Song duration exceeds limit (%s > %s)" % (info['duration'], permissions.max_song_length),
                    expire_in=30
                )

            try:
                entry, position = await player.playlist.add_entry(song_url, channel=channel, author=author)

            except exceptions.WrongEntryTypeError as e:
                if e.use_url == song_url:
                    log.warning("Determined incorrect entry type, but suggested url is the same.  Help.")

                log.debug("Assumed url \"%s\" was a single entry, was actually a playlist" % song_url)
                log.debug("Using \"%s\" instead" % e.use_url)

                return await self.cmd_play(player, channel, author, permissions, leftover_args, e.use_url)

            reply_text = "Enqueued **%s** to be played. Position in queue: %s"
            btext = entry.title

        if position == 1 and player.is_stopped:
            position = 'Up next!'
            reply_text %= (btext, position)

        else:
            try:
                time_until = await player.playlist.estimate_time_until(position, player)
                reply_text += ' - estimated time until playing: %s'
            except:
                traceback.print_exc()
                time_until = ''

            reply_text %= (btext, position, ftimedelta(time_until))

        return Response(reply_text, delete_after=30)

    async def _cmd_play_playlist_async(self, player, channel, author, permissions, playlist_url, extractor_type):
        """
        Secret handler to use the async wizardry to make playlist queuing non-"blocking"
        """

        await self.send_typing(channel)
        info = await self.downloader.extract_info(player.playlist.loop, playlist_url, download=False, process=False)

        if not info:
            raise exceptions.CommandError("That playlist cannot be played.")

        num_songs = sum(1 for _ in info['entries'])
        t0 = time.time()

        busymsg = await self.safe_send_message(
            channel, "Processing %s songs..." % num_songs)  # TODO: From playlist_title
        await self.send_typing(channel)

        entries_added = 0
        if extractor_type == 'youtube:playlist':
            try:
                entries_added = await player.playlist.async_process_youtube_playlist(
                    playlist_url, channel=channel, author=author)
                # TODO: Add hook to be called after each song
                # TODO: Add permissions

            except Exception:
                log.error("Error processing playlist", exc_info=True)
                raise exceptions.CommandError('Error handling playlist %s queuing.' % playlist_url, expire_in=30)

        elif extractor_type.lower() in ['soundcloud:set', 'bandcamp:album']:
            try:
                entries_added = await player.playlist.async_process_sc_bc_playlist(
                    playlist_url, channel=channel, author=author)
                # TODO: Add hook to be called after each song
                # TODO: Add permissions

            except Exception:
                log.error("Error processing playlist", exc_info=True)
                raise exceptions.CommandError('Error handling playlist %s queuing.' % playlist_url, expire_in=30)


        songs_processed = len(entries_added)
        drop_count = 0
        skipped = False

        if permissions.max_song_length:
            for e in entries_added.copy():
                if e.duration > permissions.max_song_length:
                    try:
                        player.playlist.entries.remove(e)
                        entries_added.remove(e)
                        drop_count += 1
                    except:
                        pass

            if drop_count:
                log.debug("Dropped %s songs" % drop_count)

            if player.current_entry and player.current_entry.duration > permissions.max_song_length:
                await self.safe_delete_message(self.server_specific_data[channel.server]['last_np_msg'])
                self.server_specific_data[channel.server]['last_np_msg'] = None
                skipped = True
                player.skip()
                entries_added.pop()

        await self.safe_delete_message(busymsg)

        songs_added = len(entries_added)
        tnow = time.time()
        ttime = tnow - t0
        wait_per_song = 1.2
        # TODO: actually calculate wait per song in the process function and return that too

        # This is technically inaccurate since bad songs are ignored but still take up time
        log.info("Processed {}/{} songs in {} seconds at {:.2f}s/song, {:+.2g}/song from expected ({}s)".format(
            songs_processed,
            num_songs,
            fixg(ttime),
            ttime / num_songs if num_songs else 0,
            ttime / num_songs - wait_per_song if num_songs - wait_per_song else 0,
            fixg(wait_per_song * num_songs))
        )

        if not songs_added:
            basetext = "No songs were added, all songs were over max duration (%ss)" % permissions.max_song_length
            if skipped:
                basetext += "\nAdditionally, the current song was skipped for being too long."

            raise exceptions.CommandError(basetext, expire_in=30)

        return Response("Enqueued {} songs to be played in {} seconds".format(
            songs_added, fixg(ttime, 1)), delete_after=30)

    async def cmd_stream(self, player, channel, author, permissions, song_url):
        """
        Usage:
            {command_prefix}stream song_link

        Enqueue a media stream.
        This could mean an actual stream like Twitch or shoutcast, or simply streaming
        media without predownloading it.  Note: FFmpeg is notoriously bad at handling
        streams, especially on poor connections.  You have been warned.
        """

        song_url = song_url.strip('<>')

        if permissions.max_songs and player.playlist.count_for_user(author) >= permissions.max_songs:
            raise exceptions.PermissionsError(
                "You have reached your enqueued song limit (%s)" % permissions.max_songs, expire_in=30
            )

        await self.send_typing(channel)
        await player.playlist.add_stream_entry(song_url, channel=channel, author=author)

        return Response(":+1:", delete_after=6)

    async def cmd_search(self, player, channel, author, permissions, leftover_args):
        """
        Usage:
            {command_prefix}search [service] [number] query

        Searches a service for a video and adds it to the queue.
        - service: any one of the following services:
            - youtube (yt) (default if unspecified)
            - soundcloud (sc)
            - yahoo (yh)
        - number: return a number of video results and waits for user to choose one
          - defaults to 1 if unspecified
          - note: If your search query starts with a number,
                  you must put your query in quotes
            - ex: {command_prefix}search 2 "I ran seagulls"
        """

        if permissions.max_songs and player.playlist.count_for_user(author) > permissions.max_songs:
            raise exceptions.PermissionsError(
                "You have reached your playlist item limit (%s)" % permissions.max_songs,
                expire_in=30
            )

        def argcheck():
            if not leftover_args:
                # noinspection PyUnresolvedReferences
                raise exceptions.CommandError(
                    "Please specify a search query.\n%s" % dedent(
                        self.cmd_search.__doc__.format(command_prefix=self.config.command_prefix)),
                    expire_in=60
                )

        argcheck()

        try:
            leftover_args = shlex.split(' '.join(leftover_args))
        except ValueError:
            raise exceptions.CommandError("Please quote your search query properly.", expire_in=30)

        service = 'youtube'
        items_requested = 3
        max_items = 10  # this can be whatever, but since ytdl uses about 1000, a small number might be better
        services = {
            'youtube': 'ytsearch',
            'soundcloud': 'scsearch',
            'yahoo': 'yvsearch',
            'yt': 'ytsearch',
            'sc': 'scsearch',
            'yh': 'yvsearch'
        }

        if leftover_args[0] in services:
            service = leftover_args.pop(0)
            argcheck()

        if leftover_args[0].isdigit():
            items_requested = int(leftover_args.pop(0))
            argcheck()

            if items_requested > max_items:
                raise exceptions.CommandError("You cannot search for more than %s videos" % max_items)

        # Look jake, if you see this and go "what the fuck are you doing"
        # and have a better idea on how to do this, i'd be delighted to know.
        # I don't want to just do ' '.join(leftover_args).strip("\"'")
        # Because that eats both quotes if they're there
        # where I only want to eat the outermost ones
        if leftover_args[0][0] in '\'"':
            lchar = leftover_args[0][0]
            leftover_args[0] = leftover_args[0].lstrip(lchar)
            leftover_args[-1] = leftover_args[-1].rstrip(lchar)

        search_query = '%s%s:%s' % (services[service], items_requested, ' '.join(leftover_args))

        search_msg = await self.send_message(channel, "Searching for videos...")
        await self.send_typing(channel)

        try:
            info = await self.downloader.extract_info(player.playlist.loop, search_query, download=False, process=True)

        except Exception as e:
            await self.safe_edit_message(search_msg, str(e), send_if_fail=True)
            return
        else:
            await self.safe_delete_message(search_msg)

        if not info:
            return Response("No videos found.", delete_after=30)

        def check(m):
            return (
                m.content.lower()[0] in 'yn' or
                # hardcoded function name weeee
                m.content.lower().startswith('{}{}'.format(self.config.command_prefix, 'search')) or
                m.content.lower().startswith('exit'))

        for e in info['entries']:
            result_message = await self.safe_send_message(channel, "Result %s/%s: %s" % (
                info['entries'].index(e) + 1, len(info['entries']), e['webpage_url']))

            confirm_message = await self.safe_send_message(channel, "Is this ok? Type `y`, `n` or `exit`")
            response_message = await self.wait_for_message(30, author=author, channel=channel, check=check)

            if not response_message:
                await self.safe_delete_message(result_message)
                await self.safe_delete_message(confirm_message)
                return Response("Ok nevermind.", delete_after=30)

            # They started a new search query so lets clean up and bugger off
            elif response_message.content.startswith(self.config.command_prefix) or \
                    response_message.content.lower().startswith('exit'):

                await self.safe_delete_message(result_message)
                await self.safe_delete_message(confirm_message)
                return

            if response_message.content.lower().startswith('y'):
                await self.safe_delete_message(result_message)
                await self.safe_delete_message(confirm_message)
                await self.safe_delete_message(response_message)

                await self.cmd_play(player, channel, author, permissions, [], e['webpage_url'])

                return Response("Alright, coming right up!", delete_after=30)
            else:
                await self.safe_delete_message(result_message)
                await self.safe_delete_message(confirm_message)
                await self.safe_delete_message(response_message)

        return Response("Oh well \N{SLIGHTLY FROWNING FACE}", delete_after=30)

    async def cmd_np(self, player, channel, server, message):
        """
        Usage:
            {command_prefix}np

        Displays the current song in chat.
        """

        if player.current_entry:
            if self.server_specific_data[server]['last_np_msg']:
                await self.safe_delete_message(self.server_specific_data[server]['last_np_msg'])
                self.server_specific_data[server]['last_np_msg'] = None

            # TODO: Fix timedelta garbage with util function
            song_progress = ftimedelta(timedelta(seconds=player.progress))
            song_total = ftimedelta(timedelta(seconds=player.current_entry.duration))

            streaming = isinstance(player.current_entry, StreamPlaylistEntry)
            prog_str = ('`[{progress}]`' if streaming else '`[{progress}/{total}]`').format(
                progress=song_progress, total=song_total
            )
            action_text = 'Streaming' if streaming else 'Playing'

            if player.current_entry.meta.get('channel', False) and player.current_entry.meta.get('author', False):
                np_text = "Now {action}: **{title}** added by **{author}** {progress}\n\N{WHITE RIGHT POINTING BACKHAND INDEX} <{url}>".format(
                    action=action_text,
                    title=player.current_entry.title,
                    author=player.current_entry.meta['author'].name,
                    progress=prog_str,
                    url=player.current_entry.url
                )
            else:
                np_text = "Now {action}: **{title}** {progress}\n\N{WHITE RIGHT POINTING BACKHAND INDEX} <{url}>".format(
                    action=action_text,
                    title=player.current_entry.title,
                    progress=prog_str,
                    url=player.current_entry.url
                )

            self.server_specific_data[server]['last_np_msg'] = await self.safe_send_message(channel, np_text)
            await self._manual_delete_check(message)
        else:
            return Response(
                'There are no songs queued! Queue something with {}play.'.format(self.config.command_prefix),
                delete_after=30
            )

    async def cmd_summon(self, channel, server, author, voice_channel):
        """
        Usage:
            {command_prefix}summon

        Call the bot to the summoner's voice channel.
        """

        if not author.voice_channel:
            raise exceptions.CommandError('You are not in a voice channel!')

        voice_client = self.voice_client_in(server)
        if voice_client and server == author.voice_channel.server:
            await voice_client.move_to(author.voice_channel)
            return

        # move to _verify_vc_perms?
        chperms = author.voice_channel.permissions_for(server.me)

        if not chperms.connect:
            log.warning("Cannot join channel \"{}\", no permission.".format(author.voice_channel.name))
            return Response(
                "```Cannot join channel \"{}\", no permission.```".format(author.voice_channel.name),
                delete_after=25
            )

        elif not chperms.speak:
            log.warning("Will not join channel \"{}\", no permission to speak.".format(author.voice_channel.name))
            return Response(
                "```Will not join channel \"{}\", no permission to speak.```".format(author.voice_channel.name),
                delete_after=25
            )

        log.info("Joining {0.server.name}/{0.name}".format(author.voice_channel))

        player = await self.get_player(author.voice_channel, create=True, deserialize=self.config.persistent_queue)

        if player.is_stopped:
            player.play()

        if self.config.auto_playlist:
            await self.on_player_finished_playing(player)

    async def cmd_pause(self, player):
        """
        Usage:
            {command_prefix}pause

        Pauses playback of the current song.
        """

        if player.is_playing:
            player.pause()

        else:
            raise exceptions.CommandError('Player is not playing.', expire_in=30)

    async def cmd_resume(self, player):
        """
        Usage:
            {command_prefix}resume

        Resumes playback of a paused song.
        """

        if player.is_paused:
            player.resume()

        else:
            raise exceptions.CommandError('Player is not paused.', expire_in=30)

    async def cmd_shuffle(self, channel, player):
        """
        Usage:
            {command_prefix}shuffle

        Shuffles the playlist.
        """

        player.playlist.shuffle()

        cards = ['\N{BLACK SPADE SUIT}', '\N{BLACK CLUB SUIT}', '\N{BLACK HEART SUIT}', '\N{BLACK DIAMOND SUIT}']
        random.shuffle(cards)

        hand = await self.send_message(channel, ' '.join(cards))
        await asyncio.sleep(0.6)

        for x in range(4):
            random.shuffle(cards)
            await self.safe_edit_message(hand, ' '.join(cards))
            await asyncio.sleep(0.6)

        await self.safe_delete_message(hand, quiet=True)
        return Response("\N{OK HAND SIGN}", delete_after=15)

    async def cmd_clear(self, player, author):
        """
        Usage:
            {command_prefix}clear

        Clears the playlist.
        """

        player.playlist.clear()
        return Response('\N{PUT LITTER IN ITS PLACE SYMBOL}', delete_after=20)

    async def cmd_skip(self, player, channel, author, message, permissions, voice_channel):
        """
        Usage:
            {command_prefix}skip

        Skips the current song when enough votes are cast, or by the bot owner.
        """

        if player.is_stopped:
            raise exceptions.CommandError("Can't skip! The player is not playing!", expire_in=20)

        if not player.current_entry:
            if player.playlist.peek():
                if player.playlist.peek()._is_downloading:
                    return Response("The next song (%s) is downloading, please wait." % player.playlist.peek().title)
                elif player.playlist.peek().is_downloaded:
                    print("The next song will be played shortly.  Please wait.")
                else:
                    print("Something odd is happening.  "
                          "You might want to restart the bot if it doesn't start working.")
            else:
                print("Something strange is happening.  "
                      "You might want to restart the bot if it doesn't start working.")

        if author.id == self.config.owner_id \
                or permissions.instaskip \
                or author == player.current_entry.meta.get('author', None):

            player.skip()  # check autopause stuff here
            await self._manual_delete_check(message)
            return

        # TODO: ignore person if they're deaf or take them out of the list or something?
        # Currently is recounted if they vote, deafen, then vote

        num_voice = sum(1 for m in voice_channel.voice_members if not (
            m.deaf or m.self_deaf or m.id in [self.config.owner_id, self.user.id]))

        num_skips = player.skip_state.add_skipper(author.id, message)

        skips_remaining = min(
            self.config.skips_required,
            sane_round_int(num_voice * self.config.skip_ratio_required)
        ) - num_skips

        if skips_remaining <= 0:
            player.skip()  # check autopause stuff here
            return Response(
                'your skip for **{}** was acknowledged.'
                '\nThe vote to skip has been passed.{}'.format(
                    player.current_entry.title,
                    ' Next song coming up!' if player.playlist.peek() else ''
                ),
                reply=True,
                delete_after=20
            )

        else:
            # TODO: When a song gets skipped, delete the old x needed to skip messages
            return Response(
                'your skip for **{}** was acknowledged.'
                '\n**{}** more {} required to vote to skip this song.'.format(
                    player.current_entry.title,
                    skips_remaining,
                    'person is' if skips_remaining == 1 else 'people are'
                ),
                reply=True,
                delete_after=20
            )

    async def cmd_volume(self, message, player, new_volume=None):
        """
        Usage:
            {command_prefix}volume (+/-)[volume]

        Sets the playback volume. Accepted values are from 1 to 100.
        Putting + or - before the volume will make the volume change relative to the current volume.
        """

        if not new_volume:
            return Response('Current volume: `%s%%`' % int(player.volume * 100), reply=True, delete_after=20)

        relative = False
        if new_volume[0] in '+-':
            relative = True

        try:
            new_volume = int(new_volume)

        except ValueError:
            raise exceptions.CommandError('{} is not a valid number'.format(new_volume), expire_in=20)

        vol_change = None
        if relative:
            vol_change = new_volume
            new_volume += (player.volume * 100)

        old_volume = int(player.volume * 100)

        if 0 < new_volume <= 100:
            player.volume = new_volume / 100.0

            return Response('updated volume from %d to %d' % (old_volume, new_volume), reply=True, delete_after=20)

        else:
            if relative:
                raise exceptions.CommandError(
                    'Unreasonable volume change provided: {}{:+} -> {}%.  Provide a change between {} and {:+}.'.format(
                        old_volume, vol_change, old_volume + vol_change, 1 - old_volume, 100 - old_volume), expire_in=20)
            else:
                raise exceptions.CommandError(
                    'Unreasonable volume provided: {}%. Provide a value between 1 and 100.'.format(new_volume), expire_in=20)

    async def cmd_queue(self, channel, player):
        """
        Usage:
            {command_prefix}queue

        Prints the current song queue.
        """

        lines = []
        unlisted = 0
        andmoretext = '* ... and %s more*' % ('x' * len(player.playlist.entries))

        if player.current_entry:
            # TODO: Fix timedelta garbage with util function
            song_progress = ftimedelta(timedelta(seconds=player.progress))
            song_total = ftimedelta(timedelta(seconds=player.current_entry.duration))
            prog_str = '`[%s/%s]`' % (song_progress, song_total)

            if player.current_entry.meta.get('channel', False) and player.current_entry.meta.get('author', False):
                lines.append("Currently Playing: **%s** added by **%s** %s\n" % (
                    player.current_entry.title, player.current_entry.meta['author'].name, prog_str))
            else:
                lines.append("Now Playing: **%s** %s\n" % (player.current_entry.title, prog_str))

        for i, item in enumerate(player.playlist, 1):
            if item.meta.get('channel', False) and item.meta.get('author', False):
                nextline = '`{}.` **{}** added by **{}**'.format(i, item.title, item.meta['author'].name).strip()
            else:
                nextline = '`{}.` **{}**'.format(i, item.title).strip()

            currentlinesum = sum(len(x) + 1 for x in lines)  # +1 is for newline char

            if currentlinesum + len(nextline) + len(andmoretext) > DISCORD_MSG_CHAR_LIMIT:
                if currentlinesum + len(andmoretext):
                    unlisted += 1
                    continue

            lines.append(nextline)

        if unlisted:
            lines.append('\n*... and %s more*' % unlisted)

        if not lines:
            lines.append(
                'There are no songs queued! Queue something with {}play.'.format(self.config.command_prefix))

        message = '\n'.join(lines)
        return Response(message, delete_after=30)

    async def cmd_clean(self, message, channel, server, author, search_range=50):
        """
        Usage:
            {command_prefix}clean [range]

        Removes up to [range] messages the bot has posted in chat. Default: 50, Max: 1000
        """

        try:
            float(search_range)  # lazy check
            search_range = min(int(search_range), 1000)
        except:
            return Response("enter a number.  NUMBER.  That means digits.  `15`.  Etc.", reply=True, delete_after=8)

        await self.safe_delete_message(message, quiet=True)

        def is_possible_command_invoke(entry):
            valid_call = any(
                entry.content.startswith(prefix) for prefix in [self.config.command_prefix])  # can be expanded
            return valid_call and not entry.content[1:2].isspace()

        delete_invokes = True
        delete_all = channel.permissions_for(author).manage_messages or self.config.owner_id == author.id

        def check(message):
            if is_possible_command_invoke(message) and delete_invokes:
                return delete_all or message.author == author
            return message.author == self.user

        if self.user.bot:
            if channel.permissions_for(server.me).manage_messages:
                deleted = await self.purge_from(channel, check=check, limit=search_range, before=message)
                return Response('Cleaned up {} message{}.'.format(len(deleted), 's' * bool(deleted)), delete_after=15)

        deleted = 0
        async for entry in self.logs_from(channel, search_range, before=message):
            if entry == self.server_specific_data[channel.server]['last_np_msg']:
                continue

            if entry.author == self.user:
                await self.safe_delete_message(entry)
                deleted += 1
                await asyncio.sleep(0.21)

            if is_possible_command_invoke(entry) and delete_invokes:
                if delete_all or entry.author == author:
                    try:
                        await self.delete_message(entry)
                        await asyncio.sleep(0.21)
                        deleted += 1

                    except discord.Forbidden:
                        delete_invokes = False
                    except discord.HTTPException:
                        pass

        return Response('Cleaned up {} message{}.'.format(deleted, 's' * bool(deleted)), delete_after=6)

    async def cmd_pldump(self, channel, song_url):
        """
        Usage:
            {command_prefix}pldump url

        Dumps the individual urls of a playlist
        """

        try:
            info = await self.downloader.extract_info(self.loop, song_url.strip('<>'), download=False, process=False)
        except Exception as e:
            raise exceptions.CommandError("Could not extract info from input url\n%s\n" % e, expire_in=25)

        if not info:
            raise exceptions.CommandError("Could not extract info from input url, no data.", expire_in=25)

        if not info.get('entries', None):
            # TODO: Retarded playlist checking
            # set(url, webpageurl).difference(set(url))

            if info.get('url', None) != info.get('webpage_url', info.get('url', None)):
                raise exceptions.CommandError("This does not seem to be a playlist.", expire_in=25)
            else:
                return await self.cmd_pldump(channel, info.get(''))

        linegens = defaultdict(lambda: None, **{
            "youtube":    lambda d: 'https://www.youtube.com/watch?v=%s' % d['id'],
            "soundcloud": lambda d: d['url'],
            "bandcamp":   lambda d: d['url']
        })

        exfunc = linegens[info['extractor'].split(':')[0]]

        if not exfunc:
            raise exceptions.CommandError("Could not extract info from input url, unsupported playlist type.", expire_in=25)

        with BytesIO() as fcontent:
            for item in info['entries']:
                fcontent.write(exfunc(item).encode('utf8') + b'\n')

            fcontent.seek(0)
            await self.send_file(channel, fcontent, filename='playlist.txt', content="Here's the url dump for <%s>" % song_url)

        return Response("\N{OPEN MAILBOX WITH RAISED FLAG}", delete_after=20)

    async def cmd_listids(self, server, author, leftover_args, cat='all'):
        """
        Usage:
            {command_prefix}listids [categories]

        Lists the ids for various things.  Categories are:
           all, users, roles, channels
        """

        cats = ['channels', 'roles', 'users']

        if cat not in cats and cat != 'all':
            return Response(
                "Valid categories: " + ' '.join(['`%s`' % c for c in cats]),
                reply=True,
                delete_after=25
            )

        if cat == 'all':
            requested_cats = cats
        else:
            requested_cats = [cat] + [c.strip(',') for c in leftover_args]

        data = ['Your ID: %s' % author.id]

        for cur_cat in requested_cats:
            rawudata = None

            if cur_cat == 'users':
                data.append("\nUser IDs:")
                rawudata = ['%s #%s: %s' % (m.name, m.discriminator, m.id) for m in server.members]

            elif cur_cat == 'roles':
                data.append("\nRole IDs:")
                rawudata = ['%s: %s' % (r.name, r.id) for r in server.roles]

            elif cur_cat == 'channels':
                data.append("\nText Channel IDs:")
                tchans = [c for c in server.channels if c.type == discord.ChannelType.text]
                rawudata = ['%s: %s' % (c.name, c.id) for c in tchans]

                rawudata.append("\nVoice Channel IDs:")
                vchans = [c for c in server.channels if c.type == discord.ChannelType.voice]
                rawudata.extend('%s: %s' % (c.name, c.id) for c in vchans)

            if rawudata:
                data.extend(rawudata)

        with BytesIO() as sdata:
            sdata.writelines(d.encode('utf8') + b'\n' for d in data)
            sdata.seek(0)

            # TODO: Fix naming (Discord20API-ids.txt)
            await self.send_file(author, sdata, filename='%s-ids-%s.txt' % (server.name.replace(' ', '_'), cat))

        return Response("\N{OPEN MAILBOX WITH RAISED FLAG}", delete_after=20)


    async def cmd_perms(self, author, channel, server, permissions):
        """
        Usage:
            {command_prefix}perms

        Sends the user a list of their permissions.
        """

        lines = ['Command permissions in %s\n' % server.name, '```', '```']

        for perm in permissions.__dict__:
            if perm in ['user_list'] or permissions.__dict__[perm] == set():
                continue

            lines.insert(len(lines) - 1, "%s: %s" % (perm, permissions.__dict__[perm]))

        await self.send_message(author, '\n'.join(lines))
        return Response("\N{OPEN MAILBOX WITH RAISED FLAG}", delete_after=20)


    @owner_only
    async def cmd_setname(self, leftover_args, name):
        """
        Usage:
            {command_prefix}setname name

        Changes the bot's username.
        Note: This operation is limited by discord to twice per hour.
        """

        name = ' '.join([name, *leftover_args])

        try:
            await self.edit_profile(username=name)

        except discord.HTTPException:
            raise exceptions.CommandError(
                "Failed to change name.  Did you change names too many times?  "
                "Remember name changes are limited to twice per hour.")

        except Exception as e:
            raise exceptions.CommandError(e, expire_in=20)

        return Response("\N{OK HAND SIGN}", delete_after=20)

    async def cmd_setnick(self, server, channel, leftover_args, nick):
        """
        Usage:
            {command_prefix}setnick nick

        Changes the bot's nickname.
        """

        if not channel.permissions_for(server.me).change_nickname:
            raise exceptions.CommandError("Unable to change nickname: no permission.")

        nick = ' '.join([nick, *leftover_args])

        try:
            await self.change_nickname(server.me, nick)
        except Exception as e:
            raise exceptions.CommandError(e, expire_in=20)

        return Response("\N{OK HAND SIGN}", delete_after=20)

    @owner_only
    async def cmd_setavatar(self, message, url=None):
        """
        Usage:
            {command_prefix}setavatar [url]

        Changes the bot's avatar.
        Attaching a file and leaving the url parameter blank also works.
        """

        if message.attachments:
            thing = message.attachments[0]['url']
        else:
            thing = url.strip('<>')

        try:
            with aiohttp.Timeout(10):
                async with self.aiosession.get(thing) as res:
                    await self.edit_profile(avatar=await res.read())

        except Exception as e:
            raise exceptions.CommandError("Unable to change avatar: {}".format(e), expire_in=20)

        return Response("\N{OK HAND SIGN}", delete_after=20)


    async def cmd_disconnect(self, server):
        await self.disconnect_voice_client(server)
        return Response("\N{DASH SYMBOL}", delete_after=20)

    async def cmd_restart(self, channel):
        await self.safe_send_message(channel, "\N{WAVING HAND SIGN}")
        await self.disconnect_all_voice_clients()
        raise exceptions.RestartSignal()

    async def cmd_shutdown(self, channel):
        await self.safe_send_message(channel, "\N{WAVING HAND SIGN}")
        await self.disconnect_all_voice_clients()
        raise exceptions.TerminateSignal()

    @dev_only
    async def cmd_breakpoint(self, message):
        log.critical("Activating debug breakpoint")
        return

    @dev_only
    async def cmd_objgraph(self, channel, func='most_common_types()'):
        import objgraph

        await self.send_typing(channel)

        if func == 'growth':
            f = StringIO()
            objgraph.show_growth(limit=10, file=f)
            f.seek(0)
            data = f.read()
            f.close()

        elif func == 'leaks':
            f = StringIO()
            objgraph.show_most_common_types(objects=objgraph.get_leaking_objects(), file=f)
            f.seek(0)
            data = f.read()
            f.close()

        elif func == 'leakstats':
            data = objgraph.typestats(objects=objgraph.get_leaking_objects())

        else:
            data = eval('objgraph.' + func)

        return Response(data, codeblock='py')

    @dev_only
    async def cmd_debug(self, message, _player, *, data):
        player = _player
        codeblock = "```py\n{}\n```"
        result = None

        if data.startswith('```') and data.endswith('```'):
            data = '\n'.join(data.rstrip('`\n').split('\n')[1:])

        code = data.strip('` \n')

        try:
            result = eval(code)
        except:
            try:
                exec(code)
            except Exception as e:
                traceback.print_exc(chain=False)
                return Response("{}: {}".format(type(e).__name__, e))

        if asyncio.iscoroutine(result):
            result = await result

        return Response(codeblock.format(result))

    async def on_message(self, message):
        await self.wait_until_ready()

        message_content = message.content.strip()
        if not message_content.startswith(self.config.command_prefix):
            return

        if message.author == self.user:
            log.warning("Ignoring command from myself ({})".format(message.content))
            return

        if self.config.bound_channels and message.channel.id not in self.config.bound_channels and not message.channel.is_private:
            return  # if I want to log this I just move it under the prefix check

        command, *args = message_content.split(' ')  # Uh, doesn't this break prefixes with spaces in them (it doesn't, config parser already breaks them)
        command = command[len(self.config.command_prefix):].lower().strip()

        handler = getattr(self, 'cmd_' + command, None)
        if not handler:
            return

        if message.channel.is_private:
            if not (message.author.id == self.config.owner_id and command == 'joinserver'):
                await self.send_message(message.channel, 'You cannot use this bot in private messages.')
                return

        if message.author.id in self.blacklist and message.author.id != self.config.owner_id:
            log.warning("User blacklisted: {0.id}/{0!s} ({1})".format(message.author, command))
            return

        else:
            log.info("{0.id}/{0!s}: {1}".format(message.author, message_content.replace('\n', '\n... ')))

        user_permissions = self.permissions.for_user(message.author)

        argspec = inspect.signature(handler)
        params = argspec.parameters.copy()

        sentmsg = response = None

        # noinspection PyBroadException
        try:
            if user_permissions.ignore_non_voice and command in user_permissions.ignore_non_voice:
                await self._check_ignore_non_voice(message)

            handler_kwargs = {}
            if params.pop('message', None):
                handler_kwargs['message'] = message

            if params.pop('channel', None):
                handler_kwargs['channel'] = message.channel

            if params.pop('author', None):
                handler_kwargs['author'] = message.author

            if params.pop('server', None):
                handler_kwargs['server'] = message.server

            if params.pop('player', None):
                handler_kwargs['player'] = await self.get_player(message.channel)

            if params.pop('_player', None):
                handler_kwargs['_player'] = self.get_player_in(message.server)

            if params.pop('permissions', None):
                handler_kwargs['permissions'] = user_permissions

            if params.pop('user_mentions', None):
                handler_kwargs['user_mentions'] = list(map(message.server.get_member, message.raw_mentions))

            if params.pop('channel_mentions', None):
                handler_kwargs['channel_mentions'] = list(map(message.server.get_channel, message.raw_channel_mentions))

            if params.pop('voice_channel', None):
                handler_kwargs['voice_channel'] = message.server.me.voice_channel

            if params.pop('leftover_args', None):
                handler_kwargs['leftover_args'] = args

            args_expected = []
            for key, param in list(params.items()):

                # parse (*args) as a list of args
                if param.kind == param.VAR_POSITIONAL:
                    handler_kwargs[key] = args
                    params.pop(key)
                    continue

                # parse (*, args) as args rejoined as a string
                # multiple of these arguments will have the same value
                if param.kind == param.KEYWORD_ONLY and param.default == param.empty:
                    handler_kwargs[key] = ' '.join(args)
                    params.pop(key)
                    continue

                doc_key = '[{}={}]'.format(key, param.default) if param.default is not param.empty else key
                args_expected.append(doc_key)

                # Ignore keyword args with default values when the command had no arguments
                if not args and param.default is not param.empty:
                    params.pop(key)
                    continue

                # Assign given values to positional arguments
                if args:
                    arg_value = args.pop(0)
                    handler_kwargs[key] = arg_value
                    params.pop(key)

            if message.author.id != self.config.owner_id:
                if user_permissions.command_whitelist and command not in user_permissions.command_whitelist:
                    raise exceptions.PermissionsError(
                        "This command is not enabled for your group ({}).".format(user_permissions.name),
                        expire_in=20)

                elif user_permissions.command_blacklist and command in user_permissions.command_blacklist:
                    raise exceptions.PermissionsError(
                        "This command is disabled for your group ({}).".format(user_permissions.name),
                        expire_in=20)

            # Invalid usage, return docstring
            if params:
                docs = getattr(handler, '__doc__', None)
                if not docs:
                    docs = 'Usage: {}{} {}'.format(
                        self.config.command_prefix,
                        command,
                        ' '.join(args_expected)
                    )

                docs = dedent(docs)
                await self.safe_send_message(
                    message.channel,
                    '```\n{}\n```'.format(docs.format(command_prefix=self.config.command_prefix)),
                    expire_in=60
                )
                return

            response = await handler(**handler_kwargs)
            if response and isinstance(response, Response):
                content = response.content
                if response.reply:
                    content = '{}, {}'.format(message.author.mention, content)

                sentmsg = await self.safe_send_message(
                    message.channel, content,
                    expire_in=response.delete_after if self.config.delete_messages else 0,
                    also_delete=message if self.config.delete_invoking else None
                )

        except (exceptions.CommandError, exceptions.HelpfulError, exceptions.ExtractionError) as e:
            log.error("Error in {0}: {1.__class__.__name__}: {1.message}".format(command, e), exc_info=True)

            expirein = e.expire_in if self.config.delete_messages else None
            alsodelete = message if self.config.delete_invoking else None

            await self.safe_send_message(
                message.channel,
                '```\n{}\n```'.format(e.message),
                expire_in=expirein,
                also_delete=alsodelete
            )

        except exceptions.Signal:
            raise

        except Exception:
            log.error("Exception in on_message", exc_info=True)
            if self.config.debug_mode:
                await self.safe_send_message(message.channel, '```\n{}\n```'.format(traceback.format_exc()))

        finally:
            if not sentmsg and not response and self.config.delete_invoking:
                await asyncio.sleep(5)
                await self.safe_delete_message(message, quiet=True)


    async def on_voice_state_update(self, before, after):
        if not self.init_ok:
            return # Ignore stuff before ready

        state = VoiceStateUpdate(before, after)

        if state.broken:
            log.voicedebug("Broken voice state update")
            return

        if state.resuming:
            log.debug("Resumed voice connection to {0.server.name}/{0.name}".format(state.voice_channel))

        if not state.changes:
            log.voicedebug("Empty voice state update, likely a session id change")
            return # Session id change, pointless event

        ################################

        log.voicedebug("Voice state update for {mem.id}/{mem!s} on {ser.name}/{vch.name} -> {dif}".format(
            mem = state.member,
            ser = state.server,
            vch = state.voice_channel,
            dif = state.changes
        ))

        if not state.is_about_my_voice_channel:
            return # Irrelevant channel

        if state.joining or state.leaving:
            log.info("{0.id}/{0!s} has {1} {2}/{3}".format(
                state.member,
                'joined' if state.joining else 'left',
                state.server,
                state.my_voice_channel
            ))

        if not self.config.auto_pause:
            return

        autopause_msg = "{state} in {channel.server.name}/{channel.name} {reason}"

        auto_paused = self.server_specific_data[after.server]['auto_paused']
        player = await self.get_player(state.my_voice_channel)

        if state.joining and state.empty() and player.is_playing:
            log.info(autopause_msg.format(
                state = "Pausing",
                channel = state.my_voice_channel,
                reason = "(joining empty channel)"
            ).strip())

            self.server_specific_data[after.server]['auto_paused'] = True
            player.pause()
            return

        if not state.is_about_me:
            if not state.empty(old_channel=state.leaving):
                if auto_paused and player.is_paused:
                    log.info(autopause_msg.format(
                        state = "Unpausing",
                        channel = state.my_voice_channel,
                        reason = ""
                    ).strip())

                    self.server_specific_data[after.server]['auto_paused'] = False
                    player.resume()
            else:
                if not auto_paused and player.is_playing:
                    log.info(autopause_msg.format(
                        state = "Pausing",
                        channel = state.my_voice_channel,
                        reason = "(empty channel)"
                    ).strip())

                    self.server_specific_data[after.server]['auto_paused'] = True
                    player.pause()


    async def on_server_update(self, before:discord.Server, after:discord.Server):
        if before.region != after.region:
            log.warning("Server \"%s\" changed regions: %s -> %s" % (after.name, before.region, after.region))

            await self.reconnect_voice_client(after)


    async def on_server_join(self, server:discord.Server):
        log.info("Bot has been joined server: {}".format(server.name))

        if not self.user.bot:
            alertmsg = "<@{uid}> Hi I'm a musicbot please mute me."

            if server.id == "81384788765712384" and not server.unavailable: # Discord API
                playground = server.get_channel("94831883505905664") or discord.utils.get(server.channels, name='playground') or server
                await self.safe_send_message(playground, alertmsg.format(uid="98295630480314368")) # fake abal

            elif server.id == "129489631539494912" and not server.unavailable: # Rhino Bot Help
                bot_testing = server.get_channel("134771894292316160") or discord.utils.get(server.channels, name='bot-testing') or server
                await self.safe_send_message(bot_testing, alertmsg.format(uid="98295630480314368")) # also fake abal

        log.debug("Creating data folder for server %s", server.id)
        pathlib.Path('data/%s/' % server.id).mkdir(exist_ok=True)

    async def on_server_remove(self, server: discord.Server):
        log.info("Bot has been removed from server: {}".format(server.name))
        log.debug('Updated server list:')
        [log.debug(' - ' + s.name) for s in self.servers]

        if server.id in self.players:
            self.players.pop(server.id).kill()


    async def on_server_available(self, server: discord.Server):
        if not self.init_ok:
            return # Ignore pre-ready events

        log.debug("Server \"{}\" has become available.".format(server.name))

        player = self.get_player_in(server)

        if player and player.is_paused:
            av_paused = self.server_specific_data[server]['availability_paused']

            if av_paused:
                log.debug("Resuming player in \"{}\" due to availability.".format(server.name))
                self.server_specific_data[server]['availability_paused'] = False
                player.resume()


    async def on_server_unavailable(self, server: discord.Server):
        log.debug("Server \"{}\" has become unavailable.".format(server.name))

        player = self.get_player_in(server)

        if player and player.is_playing:
            log.debug("Pausing player in \"{}\" due to unavailability.".format(server.name))
            self.server_specific_data[server]['availability_paused'] = True
            player.pause()
