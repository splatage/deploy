#!/bin/bash



function start () {

    screen -h 1024 -L -dmS mojo perl deploy.pl daemon -m production -l http://*:3000
    screen -h 1024 -L -dmS minion perl deploy.pl minion worker -m production -j 12
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
esac
