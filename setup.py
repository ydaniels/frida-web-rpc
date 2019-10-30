from setuptools import setup


def readme():
    with open('README.md') as f:
        return f.read()


setup(name='frida_rpc',
      version='0.1.0',
      description='Expose frida RPC as a service you can access over the web or network',
      long_description=readme(),
      classifiers=[

          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3.6+',
          'Topic :: Reverse Engineering :: Frida RPC',
      ],
      keywords='frida rpc web network internet reverse engineering',
      url='https://github.com/ydaniels/frida-web-rpc',
      author='Yomi D',
      author_email='yomid4all@gmail.com',
      license='MIT',
      packages=['frida_rpc'],
      install_requires=[
          'flask',
          'frida'
      ],
      zip_safe=False)
