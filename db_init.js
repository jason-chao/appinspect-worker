conn = Mongo();
db = conn.getDB("appinspect_prod");

db.createUser({user: "appinsp_dbuser",pwd: "[password]",roles:[{role: "dbOwner" , db:"appinsp_prod"}]})

db.createCollection("AppInspectAppEntry")
db.createCollection("AppInspectTask")
db.createCollection("AppInspectFileRecord")
db.createCollection("AppInspectStoreRecord")

db.AppInspectTask.createIndex({"Created":1, "Action":1})
db.AppInspectAppEntry.createIndex({"Id":1})
db.AppInspectFileRecord.createIndex({"AppId":1, "Created":1})
db.AppInspectStoreRecord.createIndex({"AppId":1, "Retrieved": 1})
