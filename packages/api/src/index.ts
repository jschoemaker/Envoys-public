import { buildApp } from './app.js'

const PORT = parseInt(process.env.PORT ?? '3000')
const app  = buildApp()

app.listen({ port: PORT, host: '0.0.0.0' }, (err) => {
  if (err) {
    app.log.error(err)
    process.exit(1)
  }
})
