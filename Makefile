
install: build install_configuration install_program


build:
	pycompile appfw/
	pycompile appfirewall.py

clean:
	find . -name \*.pyc -type f -delete
	find . -name __pycache__ -type d -delete

install_configuration:
	cp appfirewall.conf /etc/appfirewall.conf

install_program:
	mkdir -p /opt/appfirewall/
	cp -r * /opt/appfirewall/
	chown root:root /opt/appfirewall -R
	find /opt/appfirewall/ -type d -exec chmod u=rwx,g=rx,o= {} \;
	find /opt/appfirewall/ -type f -exec chmod u=rw,g=r,o= {} \;
	find /opt/appfirewall/ -type f -name '*.py' -exec chmod u=rwx,g=rx,o= {} \;
	chmod o+rx /opt

uninstall:
	rm -rf /opt/appfirewall
	rm -f /etc/appfirewall.conf

