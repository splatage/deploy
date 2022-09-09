#!/bin/bash



function start () {
#    git pull
    screen -h 1024 -L -dmS mojo perl deploy.pl daemon -m production -l http://*:3000
    screen -h 1024 -L -dmS minion perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j 6
    sleep 1
    screen -list
}

function test () {
    screen -h 1024 -L -dmS mojo_test1 morbo deploy.pl -l http://*:3001
    screen -h 1024 -L -dmS mojo_test2 morbo deploy.pl -l http://*:3002
    screen -h 1024 -L -dmS mojo_test3 morbo deploy.pl -l http://*:3003
    screen -h 1024 -L -dmS mojo_test4 morbo deploy.pl -l http://*:3004

#    screen -h 1024 -L -dmS minion perl deploy.pl minion worker -m production -I 15 -C 5 -R 3600 -j 6
    sleep 1
    screen -list
}



function stop () {

    screen -list | awk -F '.' '/mojo/ || /minion/ {print $1}' | xargs kill
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
