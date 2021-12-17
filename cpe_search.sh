#!/bin/bash
sqlite3 ./cpe.sqlite3 'select cpe_fs from categorized_cpes' | peco

