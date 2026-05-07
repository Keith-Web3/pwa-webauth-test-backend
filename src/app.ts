import express from 'express'
import morgan from 'morgan'
import cors from 'cors'
import 'dotenv/config'

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(morgan('dev'))
app.use(cors({ origin: process.env['ORIGIN'], credentials: true }))

export default app
