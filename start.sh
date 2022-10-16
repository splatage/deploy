#!/bin/bash
MINION_WORKERS=1
MINION_JOBS=4
MOJO_APP=deploy.pl

function start_mojo () {
    hypnotoad deploy.pl
}

function start_minions () {
    until [  ${MINION_WORKERS} -eq 0 ]; do
        echo "starting minion worker number ${MINION_WORKERS}"
	echo "screen -h 1024 -L -dmS minion${MINION_WORKERS} perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j ${MINION_JOBS}"
        screen -h 1024 -L -dmS minion${MINION_WORKERS} perl ${MOJO_APP} minion worker -m production -I 15 -C 5 -R 3600 -j ${MINION_JOBS}
        let MINION_WORKERS-=1
    done 

    sleep 1
    screen -list
}

function morbo () {
    screen -h 1024 -L -dmS mojo_test1 morbo ${MOJO_APP} -l http://*:3001
    sleep 1
    screen -list
}

function stop_screens () {
    screen -list | awk -F '.' '/mojo/ || /minion/ {print $1}' | xargs kill
    sleep 2
    screen -list
}

function stop_mojo () {
    hypnotoad -s ${MOJO_APP}
}

function cleanup_ssh_master_sockets () {
    rm .ssh_master*
    killall ssh
}

function hot_restart_mojo () {
    hypnotoad ${MOJO_APP}
}


case $1 in
    restart)
        hot_restart_mojo
        stop_screens
        start_minions
    ;;
    start)
        start_mojo
        start_minions
    ;;
    stop)
        stop_mojo
        stop_screens
        cleanup_ssh_master_sockets
   ;;
    morbo)
        morbo
    ;;
esac
