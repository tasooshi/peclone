#!/usr/bin/env python3

# =================================================
#  PEclone - a Portable Executable cloning utility
# =================================================
#
#  PEclone is a tiny but fun utility that reliably
#  copies resources of PE files using Win32 API.
#
#  http://github.com/tasooshi/peclone
#
# =================================================

__author__ = 'tasooshi'
__version__ = '0.1'

import argparse
import ctypes
import ctypes.wintypes
import mmap
import pathlib
import platform
import shutil
import sys


if platform.system() != 'Windows':
    raise RuntimeError('This program must be run under Windows-like system.')


kernel32 = ctypes.windll.kernel32
imagehlp = ctypes.windll.imagehlp


class ResourceTypes:

    RT_CURSOR = 0x01
    RT_BITMAP = 0x02
    RT_ICON = 0x03
    RT_MENU = 0x04
    RT_DIALOG = 0x05
    RT_STRING = 0x06
    RT_FONTDIR = 0x07
    RT_FONT = 0x08
    RT_ACCELERATOR = 0x09
    RT_RCDATA = 0x0a
    RT_MESSAGETABLE = 0x0b
    RT_GROUP_CURSOR = 0x0c
    RT_GROUP_ICON = 0x0e
    RT_VERSION = 0x10
    RT_DLGINCLUDE = 0x11
    RT_PLUGPLAY = 0x13
    RT_VXD = 0x14
    RT_ANICURSOR = 0x15
    RT_ANIICON = 0x16
    RT_HTML = 0x17
    RT_MANIFEST = 0x18


class LoadLibraryExFlags:

    DONT_RESOLVE_DLL_REFERENCES = 0x00000001
    LOAD_LIBRARY_AS_DATAFILE = 0x00000002
    LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
    LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010
    LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
    LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040
    LOAD_LIBRARY_REQUIRE_SIGNED_TARGET = 0x00000080
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
    LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400
    LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
    LOAD_LIBRARY_SAFE_CURRENT_DIRS = 0x00002000


EnumResNameProc = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,
    ctypes.wintypes.HMODULE,
    ctypes.wintypes.LONG,
    ctypes.wintypes.LONG,
    ctypes.wintypes.LONG,
)


EnumResLangProc = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,
    ctypes.wintypes.HMODULE,
    ctypes.wintypes.LONG,
    ctypes.wintypes.LONG,
    ctypes.wintypes.WORD,
    ctypes.wintypes.LONG,
)


class PeClone:

    RESOURCE_TYPES = (
        ResourceTypes.RT_BITMAP,
        ResourceTypes.RT_ICON,
        ResourceTypes.RT_GROUP_CURSOR,
        ResourceTypes.RT_GROUP_ICON,
        ResourceTypes.RT_VERSION,
        ResourceTypes.RT_MANIFEST,
    )

    def __init__(self, res_source, res_dest, res_final, /, res_types=None):
        if res_types is None:
            res_types = self.RESOURCE_TYPES
        self.res_source = self.to_abspath(res_source)
        self.res_dest = self.to_abspath(res_dest)
        self.res_final = self.to_abspath(res_final)
        self.res_types = res_types
        self.resources = list()
        self.languages = list()

    def to_abspath(self, path):
        return str(pathlib.Path(path).resolve())

    def add_languages(self, handle, res_type, res_name, res_lang, param=None):
        if res_lang not in self.languages:
            self.languages.append(res_lang)
        return True

    def add_resources(self, handle, res_type, res_name, param=None):
        kernel32.EnumResourceLanguagesW(
            handle,
            res_type,
            res_name,
            EnumResLangProc(self.add_languages),
            0
        )
        for res_lang in self.languages:
            resource = kernel32.FindResourceW(handle, res_name, res_type)
            res_size = kernel32.SizeofResource(handle, resource)
            data_ptr = kernel32.LoadResource(handle, resource)
            res_ptr = kernel32.LockResource(data_ptr)
            self.resources.append(
                (
                    res_type,
                    res_name,
                    res_lang,
                    ctypes.string_at(res_ptr, res_size),
                    res_size,
                )
            )
            kernel32.FreeResource(data_ptr)
        return True

    def load_resources(self):
        handle = kernel32.LoadLibraryExW(
            self.res_source,
            0,
            LoadLibraryExFlags.DONT_RESOLVE_DLL_REFERENCES |  # noqa
            LoadLibraryExFlags.LOAD_LIBRARY_AS_DATAFILE |  # noqa
            LoadLibraryExFlags.LOAD_LIBRARY_AS_IMAGE_RESOURCE
        )
        for res_type in self.res_types:
            kernel32.EnumResourceNamesW(
                handle,
                res_type,
                EnumResNameProc(self.add_resources),
                0
            )
        kernel32.FreeLibrary(handle)

    def clone_resources(self):
        # Keep the original
        shutil.copy2(self.res_dest, self.res_final)

        # Read resources from the source
        self.load_resources()

        # Actual rewrite
        handle = kernel32.BeginUpdateResourceW(self.res_final, False)
        for res_type, res_name, res_lang, res_data, res_size in self.resources:
            kernel32.UpdateResourceW(
                handle,
                res_type,
                res_name,
                res_lang,
                res_data,
                res_size
            )
        kernel32.EndUpdateResourceW(handle, False)

        # Update optional header checksum
        checksum_orig = ctypes.wintypes.DWORD()
        checksum_new = ctypes.wintypes.DWORD()
        imagehlp.MapFileAndCheckSumW(
            self.res_final,
            ctypes.byref(checksum_orig),
            ctypes.byref(checksum_new)
        )
        with pathlib.Path(self.res_final).open('r+b') as fil:
            mm = mmap.mmap(fil.fileno(), 0)
            checksum_offset = mm.find(b'PE\x00\x00') + 0x58  # A fair assumption the first occurence is the right one
            mm[checksum_offset:checksum_offset + 4] = bytearray(checksum_new)


def main():
    parser = argparse.ArgumentParser('peclone')
    parser.add_argument('-s', '--source', help='Source file (to be cloned)', required=True)
    parser.add_argument('-d', '--destination', help='Destination file (the one to pretend)', required=True)
    parser.add_argument('-o', '--output', help='Output file', required=True)
    args = parser.parse_args()
    pec = PeClone(args.source, args.destination, args.output)
    pec.clone_resources()


if __name__ == '__main__':
    sys.exit(main())
