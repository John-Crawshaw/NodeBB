'use strict';

const winston = require('winston');
const util = require('util');

const user = require('.');
const db = require('../database');
const meta = require('../meta');
const privileges = require('../privileges');
const plugins = require('../plugins');
const utils = require('../utils');

const sleep = util.promisify(setTimeout);

const Interstitials = module.exports;

// Helper function to validate email format and permission
async function validateEmail(email, allowed, error) {
	if (!allowed || !utils.isEmailValid(email)) {
		throw new Error(error);
	}
}

// Helper function to check if email change is valid
async function checkEmailChange(userData, formData, confirmed, current) {
	if (formData.email === current) {
		if (confirmed) {
			throw new Error('[[error:email-nochange]]');
		}
		if (!await user.email.canSendValidation(userData.uid, current)) {
			throw new Error(`[[error:confirm-email-already-sent, ${meta.config.emailConfirmInterval}]]`);
		}
	}
}

// Helper function to send validation email
async function sendValidationEmail(userData, formData, hasPassword, isPasswordCorrect, isSelf, req) {
	if (hasPassword && !isPasswordCorrect) {
		throw new Error('[[error:invalid-password]]');
	}

	await user.email.sendValidationEmail(userData.uid, {
		email: formData.email,
		force: true,
	}).catch((err) => {
		winston.error(`[user.interstitials.email] Validation email failed to send\n[emailer.send] ${err.stack}`);
	});
	if (isSelf) {
		req.session.emailChanged = 1;
	}
}

// Main function to validate and send email
async function validateAndSendEmail(userData, formData, req, hasPassword, isSelf) {
	const [isPasswordCorrect, canEdit, { email: current, 'email:confirmed': confirmed }, { allowed, error }] = await Promise.all([
		user.isPasswordCorrect(userData.uid, formData.password, req.ip),
		privileges.users.canEdit(req.uid, userData.uid),
		user.getUserFields(userData.uid, ['email', 'email:confirmed']),
		plugins.hooks.fire('filter:user.saveEmail', {
			uid: userData.uid,
			email: formData.email,
			registration: false,
			allowed: true,
			error: '[[error:invalid-email]]',
		}),
	]);

	if (!isPasswordCorrect) await sleep(2000);

	if (formData.email && formData.email.length) {
		await validateEmail(formData.email, allowed, error);
		await checkEmailChange(userData, formData, confirmed, current);

		if (canEdit) {
			await sendValidationEmail(userData, formData, hasPassword, isPasswordCorrect, isSelf, req);
		} else {
			throw new Error('[[error:no-privileges]]');
		}
	} else {
		await handleEmptyEmail(userData, formData, hasPassword, isPasswordCorrect, current, isSelf, req);
	}
}

// Helper function to handle empty email case
async function handleEmptyEmail(userData, formData, hasPassword, isPasswordCorrect, current, isSelf, req) {
	if (meta.config.requireEmailAddress) {
		throw new Error('[[error:invalid-email]]');
	}

	if (current.length && (!hasPassword || (hasPassword && isPasswordCorrect))) {
		await user.email.remove(userData.uid, isSelf ? req.session.id : null);
	}
}

Interstitials.get = async (req, userData) => plugins.hooks.fire('filter:register.interstitial', {
	req,
	userData,
	interstitials: [],
});

Interstitials.email = async (data) => {
	if (!data.userData) {
		throw new Error('[[error:invalid-data]]');
	}
	if (!data.userData.updateEmail) {
		return data;
	}

	const [hasPassword, hasPending] = await Promise.all([
		user.hasPassword(data.userData.uid),
		user.email.isValidationPending(data.userData.uid),
	]);

	let email;
	if (data.userData.uid) {
		email = await user.getUserField(data.userData.uid, 'email');
	}

	data.interstitials.push({
		template: 'partials/email_update',
		data: {
			email,
			requireEmailAddress: meta.config.requireEmailAddress,
			issuePasswordChallenge: hasPassword,
			hasPending,
		},
		callback: async (userData, formData) => {
			if (formData.email) {
				formData.email = String(formData.email).trim();
			}

			if (userData.uid) {
				const isSelf = parseInt(userData.uid, 10) === parseInt(data.req.uid, 10);
				await validateAndSendEmail(userData, formData, data.req, hasPassword, isSelf);
			} else {
				await handleNewUserEmail(userData, formData);
			}

			delete userData.updateEmail;
		},
	});

	return data;
};

// Helper function for new user email handling
async function handleNewUserEmail(userData, formData) {
	const { allowed, error } = await plugins.hooks.fire('filter:user.saveEmail', {
		uid: null,
		email: formData.email,
		registration: true,
		allowed: true,
		error: '[[error:invalid-email]]',
	});

	if (!allowed || (meta.config.requireEmailAddress && !(formData.email && formData.email.length))) {
		throw new Error(error);
	}

	userData.email = formData.email;
}

Interstitials.gdpr = async (data) => {
	if (!meta.config.gdpr_enabled || (data.userData && data.userData.gdpr_consent)) {
		return data;
	}
	if (!data.userData) {
		throw new Error('[[error:invalid-data]]');
	}

	if (data.userData.uid) {
		const consented = await db.getObjectField(`user:${data.userData.uid}`, 'gdpr_consent');
		if (parseInt(consented, 10)) {
			return data;
		}
	}

	data.interstitials.push({
		template: 'partials/gdpr_consent',
		data: {
			digestFrequency: meta.config.dailyDigestFreq,
			digestEnabled: meta.config.dailyDigestFreq !== 'off',
		},
		callback: (userData, formData, next) => {
			if (formData.gdpr_agree_data === 'on' && formData.gdpr_agree_email === 'on') {
				userData.gdpr_consent = true;
			}
			next(userData.gdpr_consent ? null : new Error('[[register:gdpr-consent-denied]]'));
		},
	});
	return data;
};

Interstitials.tou = async (data) => {
	if (!data.userData) {
		throw new Error('[[error:invalid-data]]');
	}
	if (!meta.config.termsOfUse || data.userData.acceptTos) {
		return data;
	}

	if (data.userData.uid) {
		const accepted = await db.getObjectField(`user:${data.userData.uid}`, 'acceptTos');
		if (parseInt(accepted, 10)) {
			return data;
		}
	}

	const termsOfUse = await plugins.hooks.fire('filter:parse.post', {
		postData: {
			content: meta.config.termsOfUse || '',
		},
	});

	data.interstitials.push({
		template: 'partials/acceptTos',
		data: {
			termsOfUse: termsOfUse.postData.content,
		},
		callback: (userData, formData, next) => {
			if (formData['agree-terms'] === 'on') {
				userData.acceptTos = true;
			}
			next(userData.acceptTos ? null : new Error('[[register:terms-of-use-error]]'));
		},
	});
	return data;
};
