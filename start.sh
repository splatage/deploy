#!/bin/bash

function start () {
#    screen -h 1024 -L -dmS mojo   perl deploy.pl prefork -m production -l http://*:3000
    MOJO_REVERSE_PROXY=1 hypnotoad deploy.pl 
    screen -h 1024 -L -dmS minion1 perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j 4
    screen -h 1024 -L -dmS minion2 perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j 4
    screen -h 1024 -L -dmS minion3 perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j 4
    sleep 1
    screen -list
}

function test () {
    screen -h 1024 -L -dmS mojo_test1 morbo deploy.pl -l http://*:3001
    sleep 1
    screen -list
}

function stop () {
    screen -list | awk -F '.' '/mojo/ || /minion/ {print $1}' | xargs kill
    hypnotoad -s deploy.pl
    sleep 2
    screen -list
}

case $1 in
    start)
        start
    ;;
    stop)
        stop
    ;;
    test)
        test
    ;;
esac
