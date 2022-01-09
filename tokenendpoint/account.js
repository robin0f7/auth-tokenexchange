import assert from 'assert';
import fs from 'fs';

var accounts = false;
var common_password = false;
class FileAccount {

    static ensureAccounts() {
        // The default memory_adapter for node-oidc imports this package (and
        // assumes it exists).

        if (accounts == false) {
            assert(process.env.ACCOUNTS_FILE, 'process.env.ACCOUNTS_FILE missing');
            assert(process.env.ACCOUNT_PASSWORD_SECRET_FILE, 'process.env.ACCOUNT_PASSWORD_SECRET_FILE missing');
            accounts = JSON.parse(fs.readFileSync(process.env.ACCOUNTS_FILE));
            common_password = fs.readFileSync(process.env.ACCOUNT_PASSWORD_SECRET_FILE, 'utf8');
        }
    }

    static async findAccount(ctx, sub, token) {
        console.log(`findAccount: looking for account sub==${sub}`)

        const account = accounts.find(account => {return account.sub == sub});

        if (!account) {
            console.log('account not found');
            return undefined;
        }
        console.log("findAccount", account);
        return {
            accountId: account.sub,
            claims: (use, scope, claims, rejected) => {
                return account;  
            }
        }
    }

    static async authenticate(email, password) {
        try {
            assert (process.env.DEVIDP_ENABLED, "basic auth not allowed")
            assert(accounts != false, "dev accounts not loaded")
            assert(password, 'password must be provided');
            assert(email, 'email must be provided');
            const account = accounts.find(account => {return account.email == String(email).toLowerCase()});
            assert(account, 'invalid email provided');
            assert(password === common_password, 'invalid credentials provided');

            return account.sub;
        } catch (err) {
            return undefined;
        }
    }
}

export default FileAccount;