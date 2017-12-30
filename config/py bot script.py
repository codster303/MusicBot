import os


num = '1'
artnum = '6'
alblet = 'a'
titlelist = []
songnum = 1
with open('output.txt', 'w') as out_file:
    with open('input.txt', 'r') as in_file:
        for line in in_file:
            if line[0].isnumeric():
                
                songnum = 1
                out_file.write("\nasync def cmd_s" + artnum + alblet + "(self, channel):"  +
		"\n\tawait self.safe_send_message(channel," +
		'\n\t"You selected: INSERT_ALBUM_HERE"\\' +
		'\n\t"\\nPlease select a song:"\\')
                for each in titlelist:
                    
                    out_file.write('\n\t"\\n!s' + artnum + alblet +  str(songnum) + " = " + each + '"\\')
                    songnum += 1

                out_file.write(")\n\n")

                artnum  = str(line[0])
                alblet = str(line[1])
                titlelist = []
                songnum = 1
                print('num: ' + str(artnum))

               
                
            else:    
                print(line)
                link = str(line).rstrip()
                out_file.write("async def cmd_s" +  artnum + alblet + str(songnum) + "(self, player ,channel, author, permissions, leftover_args):" +
                "\n\tawait self.cmd_play( player, channel, author, permissions, leftover_args, \n\t" +
                '"' + link + '")\n' +
                '\tawait self.post_lastinqueue( player ,channel, author, permissions, leftover_args)\n\n')

                slink = link.split('/track/')
                title = slink[-1].replace("-"," ")
                print(title)
                titlelist.append(title)

                songnum+=1



print("done")

