import express from 'express'
import morgan from 'morgan'
import cors from 'cors'

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(morgan('dev'))
app.use(cors({ origin: 'http://localhost:3000', credentials: true }))

export default app
