import sqlite3 as sql

memOneDb = sql.connect("membersOne.db")
cursorOne = memOneDb.cursor()
cursorOne.execute("""CREATE TABLE IF NOT EXISTS members(id_ text,Number_ text,Name_ text,Surname text,Username text,Password_ text)""")


memTwoDb = sql.connect("membersTwo.db")
cursorTwo = memTwoDb.cursor()
cursorTwo.execute("""CREATE TABLE IF NOT EXISTS members(id_ text,Gmail_ text,Name_ text,Surname text,Username text,Password_ text)""")

memIPDb = sql.connect("targets-IP.db")
memIPDbCursor = memIPDb.cursor()
memIPDbCursor.execute("""CREATE TABLE IF NOT EXISTS targets_IP(destination_ip text)""")

memURLDb = sql.connect("targets-URL.db")
memURLDbCursor = memURLDb.cursor()
memURLDbCursor.execute("""CREATE TABLE IF NOT EXISTS targets_URL(destination_url text)""")

adminDb = sql.connect("admins.db")
adminDbCursor = adminDb.cursor()
adminDbCursor.execute("""CREATE TABLE IF NOT EXISTS admins(id text,username_ text, password_ text)""")

