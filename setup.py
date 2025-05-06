from setuptools import setup, find_packages

setup(
    name='Weblet',
    version='1.1.0',
    description='Minimalist HTTP server library for Python with routing, middleware, HTTPS, templates, async, and multi-DB support',
    author='BugFreeZone',
    author_email='r96177385@gmail.com',
    url='https://github.com/BugFreeZone/Weblet',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'Jinja2>=3.0',
        'mysql-connector-python',
        'asgiref',
        'watchdog'
    ],
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
