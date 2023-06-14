from setuptools import setup

setup(
    name="zvm",
    version="0.0.1",
    py_modules=["zvm"],
    install_requires=[
        "pymongo>=3.4.0",
        "pytest>=3.3.0",
        # 'httpx>=0.7.5',
        "requests>=2.18.4",
    ],
)
