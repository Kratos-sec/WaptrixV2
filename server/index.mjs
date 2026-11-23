import { fileURLToPath } from 'node:url'
import { createApp } from './app.mjs'

const port = Number(process.env.REQUIEM_PORT ?? 4173)
const server = createApp({
  directory: process.env.REQUIEM_STATE_DIR ?? fileURLToPath(new URL('../.demo-state/', import.meta.url)),
  dist: fileURLToPath(new URL('../dist/', import.meta.url)),
})
server.listen(port, '127.0.0.1', () => console.log('Requiem demo http://127.0.0.1:' + server.address().port))
