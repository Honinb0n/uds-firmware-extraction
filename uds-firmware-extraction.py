############################################
# program name: uds-firmware-extraction
# version: 1.0.1
# date: 2024-03-04
# author: Honinbon

# GNU General Public License v2.0
############################################
 
import os, argparse

__version__ = "v1.0.1"

parser = argparse.ArgumentParser(description="Author: Honinbon\nUDS flash traffic firmware extraction tool.", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('-i', '--input', metavar='input_file', required=True, dest='input_file', \
                    help='Standard candump logfile')
parser.add_argument('-o', '--output', metavar='output_file', dest='output_file', default='./firmware.bin', \
                    help='File to store the extracted firmware. default: firmware.bin')
parser.add_argument('-s', '--s19', metavar='s19_file', dest='s19_file', \
                    help='Generate a firmware.s19 at the same time')
parser.add_argument('--flash_id', metavar='flash_id', required=True, dest='flash_id', \
                    help='Diag id used for flashing')
parser.add_argument('--split', metavar='split_symble', dest='split_symble', default="#", \
                    help='The specified symble to split canid and candata in the input file. default: "#"')
parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}', help='Display version')
args = parser.parse_args()

input_file = args.input_file
result_file = args.output_file
diagid = int(args.flash_id, 16)
split_symble = args.split_symble
s19_file = args.s19_file

red = "\033[91m"
green = "\033[92m"
yellow = "\033[93m"
blue = "\033[94m"
color_end = "\033[0m"

if os.path.exists(result_file):
    print(red+result_file[result_file.rfind("/")+1:]+ " already exists in this directory. Please change an output file name."+color_end)
    exit()
    
f1 = open(input_file, 'r')
f2 = open(result_file, 'wb')

tmpdata = ""

length = 0
tmp = ""
cnt = 0
flash = 0 

compression_method = '0'
encrypting_method = '0'

mem_size = 0
data = ""
datalen = 0
i = 0
rows_num = 0
block = ""
lastlen = 0

totle_lenth = 0

lines = f1.readlines()
for line in lines:
    line = line[line.rfind(" ")+1:]
    split_position = line.find(split_symble)
    can_id = int(line[:split_position], 16)
    can_data = line[split_position+1:].replace("\n", "")
    
    if can_id == diagid:
        ### 34
        if can_data[0:1] == "0" and can_data[2:4] == "34":
            compression_method = can_data[4:5]
            encrypting_method = can_data[5:6]
            mem_size = can_data[8+int(can_data[7:8],16)*2:(12+int(can_data[7:8],16)*2+int(can_data[6:7],16)*2)-4]
            flash += 1
            print(blue+"========> flash "+str(flash)+" start <========"+color_end)
        if can_data[0:1] == "1" and can_data[4:6] == "34":
            compression_method = can_data[6:7]
            encrypting_method = can_data[7:8]
            flash += 1
            print(blue+"========> flash "+str(flash)+" start <========"+color_end)
            lock = True
            length = int(can_data[1:4], 16) # hex byte
            if (length - 6) % 7 == 0:
                cnt = (length - 6) // 7 
            else:
                cnt = (length - 6) // 7 + 1
            tmp = can_data[4:]
        if can_data[0:1] == "2" and cnt > 0:
            tmp += can_data[2:]
            cnt -= 1
            if cnt == 0:
                mem_size_start = int(tmp[5:6], 16)*2+6
                mem_size_end = mem_size_start + int(tmp[4:5], 16)*2
                mem_size = int(tmp[mem_size_start:mem_size_end], 16)
        ### 36
        if can_data[0:1] == "1" and can_data[4:6] == "36":
            data = can_data[8:]
            block = can_data[6:8]
            datalen = int(can_data[1:4], 16)
            if (datalen - 6) % 7 == 0:
                rows_num = (datalen - 6) // 7 
                lastlen = 0
            else:
                rows_num = (datalen - 6) // 7 + 1
                lastlen = datalen - 6 - (rows_num - 1) * 7
        if can_data[0:1] == "2" and rows_num > 0:
            rows_num -= 1
            if rows_num != 0:
                data += can_data[2:]
            else:
                if lastlen == 0:
                    data += can_data[2:]
                else:
                    data += can_data[2:2+lastlen*2]
                if len(data) != (datalen-2)*2:
                    print(red+"!!! block "+block+" check error !!!\ncurrent handle frame: "+line+color_end)
                    exit()
                else:
                    totle_lenth += len(data)
                    print("==> block "+block+" extracted OK <==")
                    tmpdata += data
                data = ""
                datalen = 0
                i = 0
                block = ""
                lastlen = 0
        ### 37   
        if can_data[0:1] == "0" and can_data[2:4] == "37":
            if mem_size*2 != totle_lenth:
                print(mem_size*2, totle_lenth)
                print(red+"!!!!!! the flash "+str(flash)+" check error !!!!!!\ncurrent handle frame: "+line+color_end)
                exit()
            else:
                print(green+"===> flash "+str(flash)+" check OK. "+color_end, end="")
                if compression_method == '0':
                    print(green+"It is not compressed and "+color_end, end="")
                else:
                    print(green+"It is "+color_end+yellow+"compressed"+color_end+green+" and "+color_end, end="")
                if encrypting_method == '0':
                    print(green+"not encrypted. <==="+color_end)
                else:
                    print(red+"encrypted"+color_end+green+". <==="+color_end)
                if compression_method != '0':
                    print(yellow+"==> compression method is "+str(compression_method)+color_end)
                if encrypting_method != '0':
                    print(red+"==> encryption method is "+str(encrypting_method)+color_end)
                print()
                mem_size = 0
                totle_lenth = 0
                length = 0
                tmp = ""
                cnt = 0
                rows_num = 0
                compression_method = '0'
                encrypting_method = '0'

f2.write(bytes.fromhex(tmpdata))

if s19_file != None:
    os.system("objcopy -I binary -O srec "+result_file+" "+s19_file)