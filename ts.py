#!/usr/bin/env python

import io
import os
import struct
import zlib
import lzma
import glob
import subprocess
import json
import base64
import argparse
import zipfile
import shutil
import logging
import re
import http.server
import socketserver
import urllib
import hashlib

def compactify(list_):
	return [item for item in list_ if item is not None]

def unpack_int16(data):
	return struct.unpack('<' + 'H' * (len(data) // 2), data)

def unpack_int32(data):
	return struct.unpack('<' + 'I' * (len(data) // 4), data)

def pack_int16(*data):
	return struct.pack('<' + 'H' * len(data), *data)

def pack_int32(*data):
	return struct.pack('<' + 'I' * len(data), *data)

def ensure_dir(path):
	os.makedirs(os.path.dirname(path), exist_ok=True)

class Bundle():
	def __init__(self, name, path, source, unpack_to, options={}):
		self.name = name
		self.path = path
		self.source = source
		self.unpack_to = unpack_to
		self.cache_path = os.path.join(config['cache'], self.name)
		self.keys = options.get('keys', [])

	def create(self):
		self.source.extract(self.path, self.cache_path)

	def extract(self):
		os.makedirs(self.unpack_to, exist_ok=True)
		if self.keys:
			with CZReader(self.cache_path, self.keys) as cz:
				cz.extract(self.unpack_to)
		else:
			with DZReader(self.cache_path) as dz:
				dz.extract(self.unpack_to)
	
	def repack(self):
		if self.keys:
			writer = CZWriter(self.unpack_to, self.keys)
		else:
			writer = DZWriter(self.unpack_to)
		writer.write_to_file(self.cache_path)
		self.source.put(self.path, self.cache_path)

class Source():
	def __init__(self, name, path, target, type_, options={}):
		self.name = name
		self.path = path
		self.target = target
		self.type = type_
		self.dirty = False # finalize is called if this is true
		self.temp_path = os.path.join(config['cache'], self.name)
		if os.path.exists(self.temp_path):
			os.remove(self.temp_path)
		if self.type == 'apk':
			self.apksigner_sign_options = options.get('apksigner_sign_options', ['--ks', 'keystore.jks'])
		if self.type == 'obb':
			self.package_name = options.get('package_name', '.'.join(os.path.basename(path).split('.')[2:-1]))

	def extract(self, path, dest):
		if self.type == 'apk' or self.type == 'obb' or self.type == 'zip':
			with zipfile.ZipFile(self.path, 'r') as zip_ref:
				with zip_ref.open(path, 'r') as file:
					with open(dest, 'wb') as out_f:
						out_f.write(file.read())
	
	def put(self, path, src):
		if self.type == 'apk' or self.type == 'obb' or self.type == 'zip':
			ensure_dir(self.temp_path)
			with zipfile.ZipFile(self.temp_path, 'a') as zip_ref:
				zip_ref.write(src, path)
			self.dirty = True
	
	def finalize(self):
		if not self.dirty:
			return
		if self.type == 'apk' or self.type == 'obb' or self.type == 'zip':
			ensure_dir(self.target)
			with zipfile.ZipFile(self.path, 'r') as zip_from:
				all_entries = {info.filename: info for info in zip_from.infolist()}
				with zipfile.ZipFile(self.temp_path, 'a') as zip_to:
					existing_entries = {info.filename: info for info in zip_to.infolist()}
					for name, info in all_entries.items():
						if name not in existing_entries:
							zip_to.writestr(info, zip_from.read(name))
			if self.type == 'apk':
				if os.path.exists(self.target):
					os.remove(self.target)
				zipalign_command = ['zipalign', '-v', '4', self.temp_path, self.target]
				logger.info(f'Running command: {zipalign_command}')
				subprocess.check_call(zipalign_command)
				os.remove(self.temp_path)
				apksigner_command = ['apksigner', 'sign', *self.apksigner_sign_options, self.target]
				logger.info(f'Running command: {apksigner_command}')
				subprocess.check_call(apksigner_command)
			else:
				shutil.move(self.temp_path, self.target)

	def install(self, ignore_dirty=False):
		if not os.path.exists(self.target):
			shutil.copy(self.path, self.target)
		if self.type == 'apk':
			if not self.dirty and not ignore_dirty:
				aapt_command = ['aapt', 'dump', 'badging', self.path]
				logger.info(f'Running command: {aapt_command}')
				aapt_output = subprocess.check_output(aapt_command).decode()
				package_name = re.search(r"package: name='([^']+)'", aapt_output).group(1)
				adb_command = ['adb', 'shell', 'pm list packages']
				logger.info(f'Running command: {adb_command}')
				packages_output = subprocess.check_output(adb_command).decode().splitlines()
				if f'package:{package_name}' in packages_output:
					return
			adb_command = ['adb', 'install', '-r', self.target]
			logger.info(f'Running command: {adb_command}')
			subprocess.check_call(adb_command)
		elif self.type == 'obb':
			obb_path = os.path.join('/storage/emulated/0/Android/obb', self.package_name, os.path.basename(self.target))
			if not self.dirty and not ignore_dirty:
				adb_command = ['adb', 'shell', f'[ -e "{obb_path}" ]']
				logger.info(f'Running command: {adb_command}')
				if subprocess.call(adb_command) == 0:
					return
			# adb_command = ['adb', 'shell', f'mkdir -p {os.path.dirname(obb_path)}']
			# logger.info(f'Running command: {adb_command}')
			# subprocess.check_call(adb_command)
			adb_command = ['adb', 'push', self.target, obb_path]
			logger.info(f'Running command: {adb_command}')
			subprocess.check_call(adb_command)

class StandaloneBundle(Bundle, Source):
	def __init__(self, name, path, target, unpack_to, options={}):
		Bundle.__init__(self, name, path, self, unpack_to, options)
		Source.__init__(self, name, path, target, 'standalone', options)
		self.install_path = options['install_path']
	
	def create(self):
		shutil.copy(self.path, self.cache_path)

	def put(self, *args):
		self.dirty = True
	
	def finalize(self):
		if not self.dirty:
			return
		shutil.copy(self.cache_path, self.target)
	
	def install(self, ignore_dirty=False):
		if not self.dirty and not ignore_dirty:
			adb_command = ['adb', 'shell', f'[ -e "{self.install_path}" ]']
			logger.info(f'Running command: {adb_command}')
			if subprocess.call(adb_command) == 0:
				return
		adb_command = ['adb', 'push', self.target, self.install_path]
		logger.info(f'Running command: {adb_command}')
		subprocess.check_call(adb_command)

class DZReader():

	class DZFormatError(Exception):
		pass

	class FileEntry():
		def __init__(self, name):
			self.name = name
			self.places = []
			self.dir = None

		def __repr__(self):
			return f"FileEntry(name={self.name}, dir={self.dir})"
		
		def content(self, f):
			if not self.places:
				raise self.DZFormatError('No file places available')
			contents = None
			for place in self.places:
				new_contents = place.content(f)
				if contents and contents != new_contents:
					raise self.DZFormatError('File contents do not match at different places')
				contents = new_contents
			return contents

		def extract(self, f, dest):
			filename = os.path.join(dest, self.dir, self.name)
			ensure_dir(filename)
			with open(filename, 'wb') as out_f:
				out_f.write(self.content(f))
	
	class FilePlace():
		TYPES = {256: 'normal', 8: 'gzip', 512: 'lzma'}

		def __init__(self, file_index):
			self.offset = 0
			self.length = 0
			self.type = 'normal'
			self.file_index = file_index

		def set_data(self, offset, length, length2, type_code):
			if length != length2:
				raise self.DZFormatError('Invalid file size')
			if type_code not in self.TYPES:
				raise self.DZFormatError('Invalid file type')
			self.offset = offset
			self.length = length
			self.type = self.TYPES.get(type_code, 'normal')
		
		def content(self, f):
			f.seek(self.offset)
			if self.type == 'normal':
				return f.read(self.length)
			elif self.type == 'gzip':
				# For gzip, the header is always these 10 bytes, and there is no footer
				if f.read(10) != b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x0b':
					raise self.DZFormatError('Invalid gzip header')
				gz = zlib.decompressobj(-15)
				try:
					return gz.decompress(f.read(self.length - 10))
				except zlib.error as e:
					print(f"Error decompressing gzip data: {e}")
					return gz.unused_data or b''
			elif self.type == 'lzma':
				xz = lzma.LZMADecompressor()
				try:
					return xz.decompress(f.read(self.length))
				except lzma.LZMAError as e:
					print(f"Error decompressing lzma data: {e}")
					return xz.unused_data or b''

		def __repr__(self):
			return f"FilePlace(offset={self.offset}, length={self.length}, type={self.type})"

	def __init__(self, filename):
		self.filename = filename

	def gets(self, sep):
		result = b''
		while not result.endswith(sep):
			result += self.file.read(1)
		return result[:-len(sep)]

	def read_null_terminated(self):
		data = b''
		while (ch := self.file.read(1)) != b'\x00':
			data += ch
		return data.decode()

	def parse(self):
		f = self.file

		# Header
		if f.read(4) != b'DTRZ':
			raise self.DZFormatError('Invalid magic number')
		count, dir_count = unpack_int16(f.read(4))
		if f.read(1) != b'\x00':
			raise self.DZFormatError('Invalid header terminator')

		# File and dir list
		files = [self.FileEntry(self.read_null_terminated()) for i in range(count)]
		dirs = [None if i == 0 else self.read_null_terminated().replace('\\', '/') for i in range(dir_count)]

		# File locations
		places = [None] * (count * 2)  # Placeholder list size
		for i in range(count):
			dir_index, *place_indices = unpack_int16(self.gets(b'\xff\xff'))
			files[i].dir = dirs[dir_index]
			for j in place_indices:
				if places[j]:
					raise self.DZFormatError(f"Offset for file {i} coincides with file {places[j]['file_index']}")
				places[j] = self.FilePlace(i)

		# Offsets
		one, places_count = unpack_int16(f.read(4))
		if one != 1:
			raise self.DZFormatError('Invalid file locations row count')
		for i in range(places_count):
			places[i].set_data(*unpack_int32(f.read(16)))
		places = compactify(places)
		places.sort(key=lambda x: x.offset)
		for i in range(len(places) - 1):
			places[i].length = places[i + 1].offset - places[i].offset
		places[-1].length = self.file_size - places[-1].offset
		for place in places:
			files[place.file_index].places.append(place)

		self.file_entries = files
	
	def __enter__(self):
		self.file_size = os.path.getsize(self.filename)
		self.file = open(self.filename, 'rb')
		self.parse()
		return self
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.file.close()
		if exc_type is not None:
			print(f"Exception: {exc_value}")
		return False

	def extract(self, dest):
		if os.path.exists(dest):
			shutil.rmtree(dest)
		os.makedirs(dest)
		for file in self.file_entries:
			file.extract(self.file, dest)

class CZReader(DZReader):
	def __init__(self, filename, keys):
		super().__init__(filename)
		self.keys = [key if type(key) == bytes else base64.b64decode(key) for key in keys]
	
	def decrypt(self):
		with open(self.filename, 'rb') as f:
			data = bytearray(f.read())
		for key in self.keys:
			for i in range(len(data)):
				data[i] ^= key[i % len(key)]
		self.file = io.BytesIO(data)
		self.file_size = len(data)
	
	def __enter__(self):
		self.decrypt()
		self.parse()
		return self

class DZWriter():

	class DirEntry():
		def __init__(self, index, path):
			self.index = index
			self.path = path
			self.file_indices = []
		
		def write_location_table(self, f):
			for file_index in self.file_indices:
				f.write(pack_int16(self.index, file_index))
				f.write(b'\xff\xff')
		
		def null_terminated_path(self):
			return self.path.replace('/', '\\').encode() + b'\x00'

	class FileEntry():
		TYPES = {'normal': 256, 'gzip': 8, 'lzma': 512}

		def __init__(self, path, name):
			self.path = path
			self.name = name
			self.offset_table_offset = 0
		
		def null_terminated_name(self):
			return self.name.encode() + b'\x00'

		def populate(self, f):
			offset = f.tell()
			length = os.path.getsize(self.path)
			with open(self.path, 'rb') as file:
				f.write(file.read())
			f.seek(self.offset_table_offset)
			f.write(pack_int32(offset, length, length, self.TYPES['normal']))
			f.seek(offset + length)

	def __init__(self, path):
		self.path = path
		self.walk_files()

	def walk_files(self):
		self.dirs = [None]
		self.files = []
		for dir_name, _, filenames in os.walk(self.path):
			if not filenames:
				continue
			dir_entry = self.DirEntry(len(self.dirs), os.path.relpath(dir_name, self.path))
			self.dirs.append(dir_entry)
			for filename in filenames:
				dir_entry.file_indices.append(len(self.files))
				self.files.append(self.FileEntry(os.path.join(dir_name, filename), filename))

	def write(self, f):
		# Header
		f.write(b'DTRZ')
		f.write(pack_int16(len(self.files), len(self.dirs)))
		f.write(b'\x00')

		# File and dir list
		for file_entry in self.files:
			f.write(file_entry.null_terminated_name())
		for dir_entry in self.dirs[1:]:
			f.write(dir_entry.null_terminated_path())

		# File locations
		for dir_entry in self.dirs[1:]:
			dir_entry.write_location_table(f)
		
		# Offsets
		f.write(pack_int16(1, len(self.files)))
		for file_entry in self.files:
			file_entry.offset_table_offset = f.tell()
			f.write(b'\x00' * 16)

		# Contents
		for file_entry in self.files:
			file_entry.populate(f)

	def write_to_file(self, filename):
		with open(filename, 'wb') as f:
			self.write(f)
	
class CZWriter(DZWriter):
	def __init__(self, path, keys):
		super().__init__(path)
		self.keys = [key if type(key) == bytes else base64.b64decode(key) for key in keys]
	
	def encrypt(self, data):
		for key in self.keys:
			for i in range(len(data)):
				data[i] ^= key[i % len(key)]

	def write_to_file(self, filename):
		f = io.BytesIO()
		super().write(f)
		data = bytearray(f.getvalue())
		self.encrypt(data)
		with open(filename, 'wb') as out_f:
			out_f.write(data)

class Server:

	class Archive:
		def __init__(self, options):
			self.name = options['name']
			self.date = options.get('date')
			self.path = options['path']
			self.android_enabled = options.get('android_enabled')
			self.required_version = options.get('required_version')
			self.version_high_limit = options.get('version_high_limit')
			self.language = options.get('language')
			self.filename = options['filename']

		def list_item(self):
			with open(self.path, 'rb') as f:
				md5 = hashlib.md5(f.read()).hexdigest()
			result = f'[{self.name}]\n'
			result += f'Date={self.date}\n'
			if self.android_enabled != None:
				result += f'AndroidEnabled={'true' if self.android_enabled else 'false'}\n'
			if self.required_version != None:
				result += f'RequiredVer={self.required_version}\n'
			if self.version_high_limit != None:
				result += f'VerHighLimit={self.version_high_limit}\n'
			if self.language != None:
				result += f'Lang={self.language}\n'
			result += f'File={self.filename}\n'
			result += f'md5={md5}\n'
			return result

	def __init__(self, conf):
		self.archives = [self.Archive(options) for options in conf['archives']]
		self.handled_host = conf['host']
		self.archives_base_url = conf['archives_base_url']
		self.archive_list_filename = conf['archive_list_filename']

	def archive_list(self):
		result = f'\n[Info]\nTotal={len(self.archives)}\n\n'
		result += '\n'.join([archive.list_item() for archive in self.archives])
		return result.replace('\n', '\r\n').encode()

class RequestHandler(http.server.BaseHTTPRequestHandler):

	def do_GET(self):
		parsed_url = urllib.parse.urlparse(self.path)
		host = self.headers['Host']
		if host != server.handled_host:
			self.forward_request()
			return
		if parsed_url.path == os.path.join(server.archives_base_url, server.archive_list_filename):
			response_body = server.archive_list()
			self.send_response(http.HTTPStatus.OK)
			self.send_header('Content-Length', str(len(response_body)))
			self.end_headers()
			self.wfile.write(response_body)
			return
		for archive in server.archives:
			if parsed_url.path == os.path.join(server.archives_base_url, archive.filename):
				with open(archive.path, 'rb') as f:
					response_body = f.read()
				self.send_response(http.HTTPStatus.OK)
				self.send_header('Content-Length', str(len(response_body)))
				self.end_headers()
				self.wfile.write(response_body)
				return
		self.send_response(http.HTTPStatus.NOT_FOUND)
		self.end_headers()
		self.wfile.write(b'404 Not Found')

	def forward_request(self):
		url = self.path
		proxy_handler = urllib.request.ProxyHandler({})
		opener = urllib.request.build_opener(proxy_handler)
		urllib.request.install_opener(opener)
		with urllib.request.urlopen(url) as response:
			self.send_response(response.getcode())
			for key, value in response.getheaders():
				self.send_header(key, value)
			self.end_headers()
			self.wfile.write(response.read())

if __name__ == '__main__':
	logger = logging.getLogger(__name__)
	arg_parser = argparse.ArgumentParser()
	arg_parser.add_argument('--config', '-c', default='config.json', help='Path to config file')
	arg_subparsers = arg_parser.add_subparsers(dest='command', required=True)
	unpack_arg_parser = arg_subparsers.add_parser('unpack')
	unpack_arg_parser.add_argument('--bundles', '-b', nargs='*', help='List of bundles to unpack', default=None)
	pack_arg_parser = arg_subparsers.add_parser('pack')
	pack_arg_parser.add_argument('--bundles', '-b', nargs='*', help='List of bundles to pack; read from caches for others', default=None)
	pack_arg_parser.add_argument('--install', '-i', action='store_true', help='Install via ADB after packing')
	pack_arg_parser.add_argument('--install-ignore-dirty', '-I', action='store_true', help='Install even if the package is not modified and the app is present')
	server_arg_parser = arg_subparsers.add_parser('server')
	command_args = arg_parser.parse_args()

	config = json.load(open(command_args.config))
	logging.basicConfig(level=logging.getLevelNamesMapping()[config.get('log_level', 'INFO')])
	logger.info(f'Config file: {command_args.config}')
	if not config:
		logger.error('No config file found')
		exit(1)
	os.makedirs(config['cache'], exist_ok=True)
	sources = {}
	for name, source_options in config.get('sources', {}).items():
		sources[name] = Source(
			name=name,
			path=source_options['path'],
			target=source_options['target'],
			type_=source_options['type'],
			options=source_options
		)
	bundles = {}
	for name, bundle_options in config.get('bundles', {}).items():
		if bundle_options['source'] == 'standalone':
			bundles[name] = StandaloneBundle(
				name=name,
				path=bundle_options['path'],
				target=bundle_options['target'],
				unpack_to=bundle_options['unpack_to'],
				options=bundle_options
			)
			sources[name] = bundles[name]
		else:
			bundles[name] = Bundle(
				name=name,
				path=bundle_options['path'],
				source=sources[bundle_options['source']],
				unpack_to=bundle_options['unpack_to'],
				options=bundle_options
			)

	if command_args.command == 'unpack':
		for bundle_name in command_args.bundles or bundles.keys():
			bundle = bundles[bundle_name]
			logger.info(f'Unpacking bundle "{bundle_name}" to {bundle.unpack_to}')
			bundle.create()
			bundle.extract()
	elif command_args.command == 'pack':
		for bundle_name in command_args.bundles or bundles.keys():
			bundle = bundles[bundle_name]
			logger.info(f'Repacking bundle "{bundle_name}" from {bundle.unpack_to}')
			bundle.repack()
		for source in sources.values():
			source.finalize()
		if command_args.install:
			for source in sources.values():
				source.install(command_args.install_ignore_dirty)
	elif command_args.command == 'server':
		address = (config['server']['bind_address'], config['server']['bind_port'])
		httpd = http.server.HTTPServer(address, RequestHandler)
		server = Server(config['server'])
		logger.info(f'Starting server at {address}')
		httpd.serve_forever()
