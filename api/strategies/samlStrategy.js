const passport = require('passport');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { Strategy: SamlStrategy } = require('passport-saml');
const { findUser, createUser, updateUser } = require('~/models/userMethods');
const { getStrategyFunctions } = require('~/server/services/Files/strategies');
const { hashToken } = require('~/server/utils/crypto');
const { logger } = require('~/config');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

let crypto;
try {
  crypto = require('node:crypto');
} catch (err) {
  logger.error('[samlStrategy] crypto support is disabled!', err);
}

/**
 * Downloads an image from a URL using an access token.
 * @param {string} url
 * @returns {Promise<Buffer>}
 */
const downloadImage = async (url) => {
  try {
    const response = await fetch(url);
    if (response.ok) {
      return await response.buffer();
    } else {
      throw new Error(`${response.statusText} (HTTP ${response.status})`);
    }
  } catch (error) {
    logger.error(`[samlStrategy] Error downloading image at URL "${url}": ${error}`);
    return null;
  }
};

/**
 * Determines the full name of a user based on SAML profile and environment configuration.
 *
 * @param {Object} profile - The user profile object from SAML Connect
 * @param {string} [profile.given_name] - The user's first name
 * @param {string} [profile.family_name] - The user's last name
 * @param {string} [profile.username] - The user's username
 * @param {string} [profile.email] - The user's email address
 * @returns {string} The determined full name of the user
 */
function getFullName(profile) {
  if (process.env.SAML_NAME_CLAIM) {
    return profile[process.env.SAML_NAME_CLAIM];
  }

  if (profile.given_name && profile.family_name) {
    return `${profile.given_name} ${profile.family_name}`;
  }

  if (profile.given_name) {
    return profile.given_name;
  }

  if (profile.family_name) {
    return profile.family_name;
  }

  return profile.username || profile.email;
}

/**
 * Converts an input into a string suitable for a username.
 * If the input is a string, it will be returned as is.
 * If the input is an array, elements will be joined with underscores.
 * In case of undefined or other falsy values, a default value will be returned.
 *
 * @param {string | string[] | undefined} input - The input value to be converted into a username.
 * @param {string} [defaultValue=''] - The default value to return if the input is falsy.
 * @returns {string} The processed input as a string suitable for a username.
 */
function convertToUsername(input, defaultValue = '') {
  if (typeof input === 'string') {
    return input;
  } else if (Array.isArray(input)) {
    return input.join('_');
  }

  return defaultValue;
}

async function setupSaml() {
  try {
    const samlConfig = {
      entryPoint: process.env.SAML_ENTRY_POINT,
      issuer: process.env.SAML_ISSUER,
      callbackUrl: process.env.DOMAIN_SERVER + process.env.SAML_CALLBACK_URL,
      cert: process.env.SAML_CERT,
    };

    passport.use(
      new SamlStrategy(samlConfig, async (profile, done) => {
        try {
          logger.info(`[samlStrategy] SAML authentication received for NameID: ${profile.nameID}`);
          logger.debug('[samlStrategy] SAML profile:', profile);

          let user = await findUser({ samlId: profile.nameID });
          logger.info(
            `[samlStrategy] User ${user ? 'found' : 'not found'} with SAML ID: ${profile.nameID}`,
          );

          if (!user) {
            user = await findUser({ email: profile.email });
            logger.info(
              `[samlStrategy] User ${user ? 'found' : 'not found'} with email: ${profile.email}`,
            );
          }

          const fullName = getFullName(profile);

          let username = '';
          if (process.env.SAML_USERNAME_CLAIM) {
            username = profile[process.env.SAML_USERNAME_CLAIM];
          } else {
            username = convertToUsername(profile.username || profile.given_name || profile.email);
          }

          if (!user) {
            user = {
              provider: 'saml',
              samlId: profile.nameID,
              username,
              email: profile.email || '',
              emailVerified: true,
              name: fullName,
            };
            user = await createUser(user, true, true);
          } else {
            user.provider = 'saml';
            user.samlId = profile.nameID;
            user.username = username;
            user.name = fullName;
          }

          if (profile.picture && !user.avatar?.includes('manual=true')) {
            const imageBuffer = await downloadImage(profile.picture);
            if (imageBuffer) {
              let fileName;
              if (crypto) {
                fileName = (await hashToken(profile.nameID)) + '.png';
              } else {
                fileName = profile.nameID + '.png';
              }

              const { saveBuffer } = getStrategyFunctions(process.env.CDN_PROVIDER);
              const imagePath = await saveBuffer({
                fileName,
                userId: user._id.toString(),
                buffer: imageBuffer,
              });
              user.avatar = imagePath ?? '';
            }
          }

          user = await updateUser(user._id, user);

          logger.info(
            `[samlStrategy] Login success SAML ID: ${user.samlId} | email: ${user.email} | username: ${user.username}`,
            {
              user: {
                samlId: user.samlId,
                username: user.username,
                email: user.email,
                name: user.name,
              },
            },
          );

          done(null, user);
        } catch (err) {
          logger.error('[samlStrategy] Login failed', err);
          done(err);
        }
      }),
    );
  } catch (err) {
    logger.error('[samlStrategy]', err);
  }
}

module.exports = setupSaml;
