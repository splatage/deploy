#!/bin/bash



function start () {

    screen -h 1024 -L -dmS mojo morbo myapp.pl
     sleep 1

    screen -h 1024 -L -dmS deploy perl deploy.pl
     sleep 1

    screen -list

}


function stop () {

    screen -list | awk -F '.' '/mojo/ || /deploy/ {print $1}' | xargs kill {}
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
