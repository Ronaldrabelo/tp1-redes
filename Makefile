# Autor: Ronald Rabelo

run_serv:
	python3 srv.py $(arg1) $(arg2) $(arg3)

run_cli:
	python3 cln_ident.py $(arg1) $(arg2)