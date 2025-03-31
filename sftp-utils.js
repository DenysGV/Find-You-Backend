import SftpClient from 'ssh2-sftp-client';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const sftpConfig = {
   host: process.env.SFTP_HOST,
   port: parseInt(process.env.SFTP_PORT) || 22,
   username: process.env.SFTP_USERNAME,
   password: process.env.SFTP_PASSWORD,
   readyTimeout: 10000,
   retries: 3,
   retry_factor: 2,
   retry_minTimeout: 1000
};

const BASE_PATH = process.env.SFTP_BASE_PATH || '/fileBase';
let sftpPool = [];
const MAX_POOL_SIZE = 3;

async function getSftpClient() {
   for (const client of sftpPool) {
      if (!client.busy) {
         client.busy = true;
         return client.sftp;
      }
   }

   if (sftpPool.length < MAX_POOL_SIZE) {
      const sftp = new SftpClient();
      try {
         await sftp.connect(sftpConfig);
         const poolEntry = { sftp, busy: true, created: Date.now() };
         sftpPool.push(poolEntry);
         return sftp;
      } catch (error) {
         console.error('Ошибка подключения SFTP:', error);
         throw error;
      }
   }

   return new Promise((resolve, reject) => {
      const checkPool = setInterval(() => {
         for (const client of sftpPool) {
            if (!client.busy) {
               clearInterval(checkPool);
               client.busy = true;
               resolve(client.sftp);
               return;
            }
         }
      }, 100);

      setTimeout(() => {
         clearInterval(checkPool);
         reject(new Error('Тайм-аут ожидания SFTP-соединения'));
      }, 5000);
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
      if (!(await sftp.exists(fullPath))) {
         await sftp.mkdir(fullPath, true);
      }
      return fullPath;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function exists(remotePath) {
   const sftp = await getSftpClient();
   try {
      return await sftp.exists(path.posix.join(BASE_PATH, remotePath));
   } finally {
      releaseSftpClient(sftp);
   }
}

async function listFiles(dirPath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, dirPath);
      if (!(await sftp.exists(fullPath))) return [];
      return (await sftp.list(fullPath)).filter(item => item.type === '-').map(item => item.name);
   } finally {
      releaseSftpClient(sftp);
   }
}

async function uploadFile(localPath, remoteDirPath, newFileName) {
   const sftp = await getSftpClient();
   try {
      const fullRemoteDirPath = path.posix.join(BASE_PATH, remoteDirPath);
      if (!(await sftp.exists(fullRemoteDirPath))) {
         await sftp.mkdir(fullRemoteDirPath, true);
      }
      const fullRemotePath = path.posix.join(fullRemoteDirPath, newFileName);
      await sftp.put(localPath, fullRemotePath);
      return path.posix.join('/fileBase', remoteDirPath, newFileName);
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
   } finally {
      releaseSftpClient(sftp);
   }
}

function getPublicUrl(remotePath) {
   const BASE_URL = process.env.FILE_SERVER_URL || 'https://files.yourdomain.com';
   return `${BASE_URL}${remotePath}`;
}

function cleanupConnections() {
   const now = Date.now();
   const MAX_IDLE_TIME = 60000;
   sftpPool = sftpPool.filter(client => {
      if (!client.busy && client.lastUsed && now - client.lastUsed > MAX_IDLE_TIME) {
         client.sftp.end().catch(console.error);
         return false;
      }
      return true;
   });
}

setInterval(cleanupConnections, 30000);

process.on('SIGINT', async () => {
   console.log('Закрытие SFTP соединений...');
   for (const client of sftpPool) {
      try {
         await client.sftp.end();
      } catch (error) {
         console.error('Ошибка закрытия SFTP соединения:', error);
      }
   }
   process.exit(0);
});

export { createDirectory, exists, listFiles, uploadFile, deleteFile, getPublicUrl };
