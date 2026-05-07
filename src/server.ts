import 'dotenv/config'
import { Router, type Handler } from 'express'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  type AuthenticatorTransportFuture,
  type CredentialDeviceType,
  type Base64URLString,
  type PublicKeyCredentialCreationOptionsJSON,
  type VerifiedRegistrationResponse,
  type PublicKeyCredentialRequestOptionsJSON,
  generateAuthenticationOptions,
} from '@simplewebauthn/server'

import app from './app.ts'

const rpName = 'SimpleWebAuthn Example'

const rpID = process.env['RP_ID']!

type UserModel = {
  id: any
  username: string
}

type Passkey = {
  // SQL: Store as `TEXT`. Index this column
  id: Base64URLString
  // SQL: Store raw bytes as `BYTEA`/`BLOB`/etc...
  //      Caution: Node ORM's may map this to a Buffer on retrieval,
  //      convert to Uint8Array as necessary
  publicKey: Uint8Array
  // SQL: Foreign Key to an instance of your internal user model
  user: UserModel
  // SQL: Store as `TEXT`. Index this column. A UNIQUE constraint on
  //      (webAuthnUserID + user) also achieves maximum user privacy
  webauthnUserID: Base64URLString
  // SQL: Consider `BIGINT` since some authenticators return atomic timestamps as counters
  counter: number
  // SQL: `VARCHAR(32)` or similar, longest possible value is currently 12 characters
  // Ex: 'singleDevice' | 'multiDevice'
  deviceType: CredentialDeviceType
  // SQL: `BOOL` or whatever similar type is supported
  backedUp: boolean
  // SQL: `VARCHAR(255)` and store string array as a CSV string
  // Ex: ['ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb']
  transports?: AuthenticatorTransportFuture[]
}

let currentOptions: PublicKeyCredentialCreationOptionsJSON
let registrationOptions: PublicKeyCredentialRequestOptionsJSON
let verifiedRegistration: VerifiedRegistrationResponse
let passKeys: Passkey[] = []

const webAuthRouter = Router()

const webAuthHandler: Handler = async (req, res) => {
  const { email } = req.body

  const options: PublicKeyCredentialCreationOptionsJSON =
    await generateRegistrationOptions({
      rpName,
      rpID,
      userName: email,
      // Don't prompt users for additional information about the authenticator
      // (Recommended for smoother UX)
      attestationType: 'none',
      authenticatorSelection: {
        // Defaults
        residentKey: 'preferred',
        userVerification: 'preferred',
        // Optional
        authenticatorAttachment: 'platform',
      },
    })

  console.log({ user: options.user })

  //NOTE: The generated `options` should be associated with a user account and stored in the database
  currentOptions = options
  res.status(200).json(options)
}

const verifyResponse: Handler = async (req, res) => {
  const body = req.body

  const verification = await verifyRegistrationResponse({
    response: body,
    expectedChallenge: currentOptions.challenge,
    expectedOrigin: process.env['ORIGIN']!,
    expectedRPID: rpID,
  })

  verifiedRegistration = verification

  const { credential, credentialBackedUp, credentialDeviceType } =
    verifiedRegistration.registrationInfo!

  //NOTE: The passkey information should be stored in the database and associated with a user account
  passKeys.push({
    // `user` here is from Step 2
    user: {
      id: currentOptions.user.id,
      username: currentOptions.user.name,
    },
    // Created by `generateRegistrationOptions()` in Step 1
    webauthnUserID: currentOptions.user.id,
    // A unique identifier for the credential
    id: credential.id,
    // The public key bytes, used for subsequent authentication signature verification
    publicKey: credential.publicKey,
    // The number of times the authenticator has been used on this site so far
    counter: credential.counter,
    // How the browser can talk with this credential's authenticator
    transports: credential.transports || [],
    // Whether the passkey is single-device or multi-device
    deviceType: credentialDeviceType,
    // Whether the passkey has been backed up in some way
    backedUp: credentialBackedUp,
  })
  res.status(200).json(verification)
}

const getAuthenticationOptions: Handler = async (req, res) => {
  const { email } = req.body

  const options: PublicKeyCredentialRequestOptionsJSON =
    await generateAuthenticationOptions({
      rpID,
      // Require users to use a previously-registered authenticator
      allowCredentials: passKeys
        .filter(pk => pk.user.username === email)
        .map(pk => ({
          id: pk.id,
          transports: pk.transports || [],
        })),
      userVerification: 'required',
    })

  //NOTE: The generated `options` should be associated with a user account and stored in the database
  registrationOptions = options

  res.status(200).json(options)
}

const verifyAuthentication: Handler = async (req, res) => {
  const passKey = passKeys.find(pk => pk.id === req.body.id)!

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge: registrationOptions.challenge,
    expectedOrigin: process.env['ORIGIN']!,
    expectedRPID: rpID,
    credential: {
      id: passKey.id,
      counter: passKey.counter,
      transports: passKey.transports || [],
      publicKey: passKey.publicKey as Uint8Array<ArrayBuffer>,
    },
  })

  res.status(200).json(verification)
}

webAuthRouter.route('/').post(webAuthHandler)
webAuthRouter.route('/verify').post(verifyResponse)
webAuthRouter.route('/authenticate').post(getAuthenticationOptions)
webAuthRouter.route('/verify-authentication').post(verifyAuthentication)

app.use('/', webAuthRouter)

app.listen(4000, () => {
  console.log('Server is running on port 4000')
})
