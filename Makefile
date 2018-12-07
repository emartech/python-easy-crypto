.PHONY:install-test test
test:
	python3 -m unittest discover test 'test_*.py'
install-test:
	pip install -e .[dev]
