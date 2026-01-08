.PHONY: install demo test ui clean help

help:
	@echo "SOC-Style Log Detective - Available commands:"
	@echo "  make install  - Install package in dev mode with dependencies"
	@echo "  make demo     - Run demo analysis on sample data"
	@echo "  make test     - Run all tests with pytest"
	@echo "  make ui       - Launch Streamlit UI"
	@echo "  make clean    - Remove output directory"

install:
	pip install -e ".[dev]"

demo: clean
	python -m log_detective demo

test:
	pytest tests/ -v

ui:
	streamlit run src/log_detective/ui_streamlit.py

clean:
	@if exist out rmdir /s /q out
	@echo Cleaned output directory
