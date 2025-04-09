import SftpClient from 'ssh2-sftp-client';
import path from 'path';
import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

const sftpConfig = {
   host: process.env.SFTP_HOST,
   port: parseInt(process.env.SFTP_PORT) || 22,
   username: process.env.SFTP_USERNAME,
   password: process.env.SFTP_PASSWORD,
   readyTimeout: 15000,
   retries: 5,
   retry_factor: 2,
   retry_minTimeout: 1000
};

const BASE_PATH = process.env.SFTP_BASE_PATH || '/fileBase';
let sftpPool = [];
const MAX_POOL_SIZE = 5;

async function getSftpClient() {
   for (const client of sftpPool) {
      if (!client.busy) {
         client.busy = true;
         client.lastUsed = Date.now();
         return client.sftp;
      }
   }

   if (sftpPool.length < MAX_POOL_SIZE) {
      const sftp = new SftpClient();
      try {
         await sftp.connect(sftpConfig);
         const poolEntry = { sftp, busy: true, created: Date.now(), lastUsed: Date.now() };
         sftpPool.push(poolEntry);
         return sftp;
      } catch (error) {
         throw error;
      }
   }

   return new Promise((resolve, reject) => {
      const checkPool = setInterval(() => {
         for (const client of sftpPool) {
            if (!client.busy) {
               clearInterval(checkPool);
               client.busy = true;
               client.lastUsed = Date.now();
               resolve(client.sftp);
               return;
            }
         }
      }, 100);

      setTimeout(() => {
         clearInterval(checkPool);
         reject(new Error('Тайм-аут ожидания SFTP-соединения'));
      }, 10000);
   });
}

function releaseSftpClient(sftp) {
   for (const client of sftpPool) {
      if (client.sftp === sftp) {
         client.busy = false;
         client.lastUsed = Date.now();
         return;
      }
   }
}

async function createDirectory(dirPath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, dirPath);

      const dirExists = await sftp.exists(fullPath);
      if (!dirExists) {
         await sftp.mkdir(fullPath, true);
      }
      return fullPath;
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function exists(remotePath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, remotePath);
      const exists = await sftp.exists(fullPath);
      return exists;
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function listFiles(dirPath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, dirPath);

      if (!(await sftp.exists(fullPath))) {
         return [];
      }

      const files = await sftp.list(fullPath);
      const fileNames = files.filter(item => item.type === '-').map(item => item.name);
      return fileNames;
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function uploadFile(localPath, remoteDirPath, newFileName) {
   const sftp = await getSftpClient();
   try {
      const fullRemoteDirPath = path.posix.join(BASE_PATH, remoteDirPath);

      if (!fs.existsSync(localPath)) {
         throw new Error(`Локальный файл не существует: ${localPath}`);
      }
      const stats = fs.statSync(localPath);

      if (!(await sftp.exists(fullRemoteDirPath))) {
         await sftp.mkdir(fullRemoteDirPath, true);
      }

      const fullRemotePath = path.posix.join(fullRemoteDirPath, newFileName);

      const readStream = fs.createReadStream(localPath);
      await sftp.put(readStream, fullRemotePath);

      const remoteExists = await sftp.exists(fullRemotePath);
      if (!remoteExists) {
         throw new Error(`Файл не был загружен: ${fullRemotePath}`);
      }

      return path.posix.join(remoteDirPath, newFileName);
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function deleteFile(remotePath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, remotePath);

      if (await sftp.exists(fullPath)) {
         await sftp.delete(fullPath);
      }
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

function getPublicUrl(remotePath) {
   const normalizedPath = remotePath.startsWith('/') ? remotePath : `/${remotePath}`;
   const BASE_URL = process.env.FILE_SERVER_URL || 'http://109.205.182.161';

   let publicPath = normalizedPath;
   if (BASE_PATH === '/fileBase' && normalizedPath.startsWith('/fileBase')) {
      publicPath = normalizedPath;
   } else {
      publicPath = path.posix.join(BASE_PATH, normalizedPath);
   }

   const url = `${BASE_URL}${publicPath}`;
   return url;
}

function cleanupConnections() {
   const now = Date.now();
   const MAX_IDLE_TIME = 120000;
   const initialCount = sftpPool.length;

   sftpPool = sftpPool.filter(client => {
      if (!client.busy && client.lastUsed && now - client.lastUsed > MAX_IDLE_TIME) {
         client.sftp.end().catch(() => { });
         return false;
      }
      return true;
   });
}

setInterval(cleanupConnections, 30000);

process.on('SIGINT', async () => {
   for (const client of sftpPool) {
      try {
         await client.sftp.end();
      } catch (error) {
         // Ignore errors during shutdown
      }
   }
   process.exit(0);
});

async function testConnection() {
   const sftp = await getSftpClient();
   try {
      await sftp.list(BASE_PATH);
      return true;
   } catch (error) {
      return false;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function deleteRemoteDirectory(remotePath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, remotePath);

      const exists = await sftp.exists(fullPath);
      if (!exists) {
         return;
      }

      const list = await sftp.list(fullPath);

      for (const item of list) {
         const itemPath = path.posix.join(fullPath, item.name);

         if (item.type === '-') {
            await sftp.delete(itemPath);
         } else if (item.type === 'd') {
            if (item.name !== '.' && item.name !== '..') {
               await deleteRemoteDirectory(path.posix.join(remotePath, item.name));
            }
         }
      }

      await sftp.rmdir(fullPath);
   } catch (error) {
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

export {
   createDirectory,
   exists,
   listFiles,
   uploadFile,
   deleteFile,
   deleteRemoteDirectory,
   getPublicUrl,
   testConnection,
   getSftpClient,
   releaseSftpClient
};