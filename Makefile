.PHONY:install-test test
test:
	python -m unittest discover test 'test_*.py'
install-test:
	pip install -e .[dev]