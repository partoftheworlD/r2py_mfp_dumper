import r2pipe
import re

re_temp = re.compile(r'0x[0-9a-f]{2,4}\]')

def fnc_1():
    try:
        r2 = r2pipe.open("UnityPlayer.dll", ["-B 0x0"])
        if r2:
            sign_base = search(r2, "48893d........ff15........3935........")
            sign_offset = search(r2, "0f11..........410f28..e8........410f28..f30f11....")
            base = str(hex(get_ptr(r2, sign_base))).upper()[2:]
            offset = str(hex(get_offset(r2, sign_offset))).upper()[2:]
            print(f"[Chapter time address] - \"Unityplayer.dll\" : 0x{base}, 0x{offset}")
        r2.quit()
    except BrokenPipeError:
        print("Put UnityPlayer.dll in the script folder.")

def get_offset(h_r2, flag):
    h_r2.cmd('s ' + str(flag))
    info = h_r2.cmd("pd -40~rbx")
    info = re.findall(re_temp, info)
    return int(info[0][2:-1], 16) + int(info[1][2:-1], 16) + 4

def get_ptr(h_r2, flag):
    h_r2.cmd('s '+ str(flag))
    return h_r2.cmdj('pdj 1')[0]["ptr"]

def search(h_r2, signature):
    return h_r2.cmdj('/xj ' + signature)[0]["offset"]

if __name__ == '__main__':
    fnc_1()