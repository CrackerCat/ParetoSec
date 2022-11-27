import argparse
import subprocess


parser = argparse.ArgumentParser(
    prog = 'debugActivity',
    description = 'start a debug activity',
    epilog = '-p packageNmae\n -a AcivityName')



if __name__ == '__main__':
    # parser.add_argument('filename')
    parser.add_argument('-p', '--package')
    parser.add_argument('-a' , '--activity')

    args = parser.parse_args()
    package = args.package
    activity = args.activity

    startcom = "adb shell am start -D {0}/{1}".format(package,activity)

    subprocess.run(startcom , shell=True , check=True)

    getpid = "adb shell \" ps | grep {0} | awk '{{print $2}}'\"".format(package);
    print(getpid)

    spid = subprocess.run(getpid,shell=True , capture_output=True , text=True).stdout

    subprocess.run("adb forward tcp:8700 jdwp:{0}".format(spid))

    input("Press Enter to run app...")
    proc = subprocess.run("jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700", text=True )


    # print(args.filename ,args.count , args.verbose )
