#!/bin/bash
#
#
VERSION=0.0.1
PHOST="0"
PNET="0"
DEV="alb_1"
#NUMOFPL=`cat /etc/hosts| grep PL_2_|wc -l`
#SERVERIP=`ifconfig -a bond0| grep "inet addr"|awk '{ print $2}'|awk 'BEGIN{FS=":"} {print $2}'`
HOSTPL=`cat /etc/hosts| grep PL_2_| awk '{print $2}'`
PID=""
FLAG_S=0

print_usage()
{
        echo "./start.sh -[h|help]    : get the help information"
        echo "./start.sh -[v|version] : check the version of script"
        echo "./start.sh -[b|start]   : Start the process on each Payload board"
        echo "./start.sh -[s|status]  : Check the running status of each Payload"
	echo "./start.sh -[d|dev]     : Capture interface, default is alb_1"
	echo "e.g.: ./start.sh -b -d alb_2"
        echo "./start.sh -[p|stop]    : Stop all running process in each Payload"
        echo "./start.sh -[H|host]    : Capture the Specified IP address package,"
        echo "                          need to be used with -b(-start) option."
        echo " e.g.: ./start.sh -b -H 10.149.62.4"
        echo "./start.sh -[n|net] (un-support yet)    : Capture the specified net addresses package,"
        echo "                          need to be used with -b(-start) option."
        echo " e.g.: ./start.sh -b -n 10.149.0.0/16"
}
print_version()
{
        echo "The Version is:  $VERSION."
}

start_client ()
{
if [ -x /cluster/tmp/TraceLdap ]; then

        SERVERIP=`ifconfig -a bond0| grep "inet addr"|awk '{ print $2}'|awk 'BEGIN{FS=":"} {print $2}'`
#        SERVERIP="192.168.0.1"
        if [ $SERVERIP != "192.168.0.1" ]; then
                echo "Please run this in control nodes(SC_2_1)!";
                exit

        fi
        if [ $DEV != "alb_1" -a $DEV != "alb_2" -a $DEV != "i4dd1" -a $DEV != "i4dd2" -a $DEV != "i4dd3" -a $DEV != "any" ];then
        	echo "Please check the input device for capture(-d), it can be one of this:"
        	echo "alb_1(Default), alb_2, i4dd1,i4dd2,i4dd3(i4ddx for 11B version), any. (any is working for VM)"
        	exit
        fi
        NUMOFPL=`cat /etc/hosts| grep PL_2_|wc -l`

        #Debug on VM
#        NUMOFPL=1
        sleep 1
        PLnum=`cat /etc/hosts| grep PL_2_| awk '{print $2}'| awk 'BEGIN{FS="_"} {print $3}'`
#        PLnum=3
#IP vaild check


        CMD="/cluster/tmp/TraceLdap"

        for a in $PLnum;
        do
                host="PL_2_"$a
                PLIP="192.168.0."$a

echo "HOST: $host"
echo "PLIP: $PLIP"
echo "DEV : $DEV"
        if [ $PHOST != "0" ]; then
                ssh $host $CMD $PLIP $SERVERIP $PHOST $DEV >/dev/null &
        else

                ssh $host $CMD $PLIP $SERVERIP NULL $DEV>/dev/null &
                #ssh $PLIP $CMD $PLIP $SERVERIP 2>&1 &
        fi
        done

else
        echo "Program was not found. Please put the program under below path,"
        echo " and make sure the file is executable: try chmod +x"
        echo "Path: /cluster/tmp/    File:TraceLdap."
        exit

fi
        exit 0
}

get_pid_client(){

        PRG=TraceLdap;
        PID=`ssh $1 ps -ef |grep $PRG | awk '{print $2}'`
#       echo "Debug:PID:$PID"
}
kill_pid (){
        ssh $1 kill -9 $2;
        echo "kill host:$1 pid:$2"
}
status_client (){

        echo "The running process pid list in all PLs"
        for o in $HOSTPL;
                do
                echo "====$o===="
                get_pid_client $o
                echo "pid:$PID"
        done;
        exit 0
}

stop_client(){
        echo    "Starting to terminal process...."
        echo    "Fetch PID list."
        for a in $HOSTPL;do
                {
                echo "===$a==="
                get_pid_client $a
                for p in $PID;do
                        #echo "$p"
                        kill_pid $a $p
                done

                echo "===$a:Done=="
        }
        done

        echo    "Finished."
        echo "Postcheck the process:"
        status_client

        exit 0
}


parse_options()
{

        # when no arguments, print help and exit
        if [ $# -eq 0 ]
        then
                print_usage
                exit 1
        fi
        parsed_options=$(getopt -n "$0" -o hvbsd:pH:n: -l help,version,start,status,dev:,stop,host:,net: -- $@)
        option_ret=$?
        eval set -- "$parsed_options"
        # if option parsing failed
        if [ $option_ret -ne 0 ]
        then
                print_usage
                exit 1
        fi

        # walk through options
        while [ $# -ge 1 ]
        do
                case $1 in
                        -h | --help ) print_usage;exit 0;;
                        -v | --version ) print_version;exit 0;;
                        -b | --start) FLAG_S=1;;
                        -s | --status ) status_client;exit 0;;
                        -d | --dev ) DEV=$2;echo "The input DEV:$DEV";shift;;
                        -p | --stop ) stop_client;;
                        -H | --host ) PHOST=$2;shift;;
 #                       -n | --net ) PNET=$2;shift;;
                        -- ) shift;break;;
                        * ) echo "Unsupported parameter $1";exit 2;;
                esac
                shift
        done

}

echo "Start"
##############Parameter check##########################
parse_options $*
if [ $FLAG_S == 1 ];then
	start_client
else
	print_usage
fi
######################################################
