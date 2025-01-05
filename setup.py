from setuptools import setup, find_packages

setup(
    name='smbenum',
    author="Sean Brady",
    author_email="swangeon@gmail.com",
    description="Program to enumerate an smb server for information that could be useful.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Swangeon/smbenum",
    python_requires=">=3.12",
    version='0.1.0',
    license="GNU GPL3",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "colorama>=0.4.6",
        "impacket>=0.12.0",
        "prettytable>=3.12.0"
    ],
    setup_requires=['flake8'],
)
