from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
#Authentication
gauth = GoogleAuth()
gauth.LocalWebserverAuth() 
drive = GoogleDrive(gauth)

user_file  =  input("Nhap ten nguoi dung : ")
#tao mot nguoi dung moi
def create_folder(parent_folder_id):
  newFolder = drive.CreateFile({'title': parent_folder_id,"mimeType": "application/vnd.google-apps.folder"})
  newFolder.Upload()
  return newFolder
create_folder(user_file)
#tao cert va private key
def upload_file(title_drive_folder,file_name):
  file_list = drive.ListFile({'q': "title='%s' and mimeType='application/vnd.google-apps.folder' and trashed=false" % title_drive_folder}).GetList()
  parent_folder = file_list[0]
  file = drive.CreateFile({
  'title': file_name,
  'parents': [{'kind': 'drive#fileLink', 'id': parent_folder['id']}],
  'mimeType': 'txt'
  })
  file.Upload()
  with open(file_name,'r',encoding='UTF-8') as upload_file:
    file.SetContentString(upload_file.read())
  file.Upload()
  return file
with open('cert_&_key','w',encoding='utf-8') as cp, open('key_ouput','r',encoding='utf-8') as key, open('cert.txt','r',encoding='utf-8') as cert:
  


  file_content = drive.CreateFile({'id': file_id})
  file_content.GetContentFile(file_name)
  with open(file_name, 'r') as f:
    data = f.read()
  return data
get_id = download_file_content(wanted_user,id)
get_key = download_file_content(wanted_user,key)
print(get_id)
print(get_key)"""