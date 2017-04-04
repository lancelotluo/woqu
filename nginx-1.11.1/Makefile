
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/luocn99/nginx/nginx -t

	kill -USR2 `cat /home/luocn99/nginx/nginx.pid`
	sleep 1
	test -f /home/luocn99/nginx/nginx.pid.oldbin

	kill -QUIT `cat /home/luocn99/nginx/nginx.pid.oldbin`
