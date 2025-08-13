from setuptools import setup, find_packages

setup(
    name="lightscan",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "html5lib",
        "jinja2>=3.1.2"
    ],
    entry_points={
        "console_scripts": [
            "lightscan=scanner.cli:main"
        ]
    },
    python_requires=">=3.11"
)
