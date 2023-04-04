/**
 * Test helper functions.
 */
// import * as h from './helper.mjs';
import * as h from '@ibgib/helper-gib';
import { decodeHexStringToString, encodeStringToHexString } from './helper.mjs';


const SOME_STRING = "This is some stringy stuff...";
const SOME_STRING_HASH = "5DC14EA1027B956AD6BA51F11372DF823FCF3429B5F2063F1DDA358E0F4F2992";
const SOME_OTHER_STRING = "This is quite a different string of stuff.";

describe(`when cloning`, () => {

    it(`should copy deep objects`, async () => {
        const objSimple = { a: SOME_STRING };
        const objADeep = {
            levelOne: {
                levelTwo: {
                    buckle: "your shoe",
                    three: "four",
                    objSimple: objSimple,
                }
            }
        };
        const cloneADeep = h.clone(objADeep);
        expect(cloneADeep?.levelOne?.levelTwo?.buckle).toEqual("your shoe");
        expect(cloneADeep?.levelOne?.levelTwo?.three).toEqual("four");
        expect(cloneADeep?.levelOne?.levelTwo?.objSimple).toEqual(objSimple);

        cloneADeep.levelOne.levelTwo.objSimple.a = SOME_OTHER_STRING;

        // original should **still** be the first value
        expect(objSimple.a).toEqual(SOME_STRING);
        // clone should be changed.
        expect(cloneADeep.levelOne.levelTwo.objSimple.a).toEqual(SOME_OTHER_STRING);
    });
});

describe(`when getting timestamp`, () => {
    it(`should get the current date as UTCString`, async () => {
        // implementation detail hmm....
        const timestamp = h.getTimestamp();
        const date = new Date(timestamp);
        const dateAsUTCString = date.toUTCString();
        expect(timestamp).toEqual(dateAsUTCString);
    });
});

describe(`when hashing (helper)`, () => {
    it(`should hash consistently with implicit sha256`, async () => {
        const hash = await h.hash({s: SOME_STRING}) || "";
        expect(hash.toUpperCase()).toEqual(SOME_STRING_HASH);
    });
    it(`should hash consistently with explicit sha256`, async () => {
        const hash = await h.hash({s: SOME_STRING, algorithm: "SHA-256"}) || "";
        expect(hash.toUpperCase()).toEqual(SOME_STRING_HASH);
    });
    it(`should hash without collisions, 1000 times`, async () => {
        const hashes: string[] = [];
        const salt = await h.getUUID(1024);
        // console.log(`salt: ${salt}`);
        for (let i = 0; i < 1000; i++) {
            const hash = await h.hash({s: salt + i.toString(), algorithm: "SHA-256"}) || "";
            // console.log(hash);
            expect(hashes).not.toContain(hash);
            hashes.push(hash);
        }
    });
});

describe(`when generating UUIDs`, () => {
    it(`shouldn't duplicate UUIDs`, async () => {
        const ids: string[] = [];
        for (let i = 0; i < 100; i++) {
            const id = await h.getUUID();
            expect(ids).not.toContain(id);
            ids.push(id);
        }
    });
});

const DATA_ONLY_A = `a`;
const DATA_ONLY_HEX = `0123456789abcdef`;
const DATA_ONLY_ALPHAS = `SimpleNoSpaceNoNumbersNada`;
const DATA_WITH_SPACES = `I have spaces but nothing else`;
const DATA_WITH_SPACES_AND_SOME_CHARS = `I have spaces, commas, and these other things.|+_)(*&^%$#@!)`;
const DATA_WITH_SPACES_AND_SOME_CHARS_NEW_LINES = `i have lines and

new lines

also`;

const DATA_WITH_AWS_CREDENTIALS_ENTIRE_PARAGRAPH  = `
Custom password policy options
When you configure a custom password policy for your account, you can specify the following conditions:

•	Password minimum length – You can specify a minimum of 6 characters and a maximum of 128 characters.
•	Password strength – You can select any of the following check boxes to define the strength of your IAM user passwords:
•	Require at least one uppercase letter from Latin alphabet (A–Z)
•	Require at least one lowercase letter from Latin alphabet (a–z)
•	Require at least one number
•	Require at least one nonalphanumeric character ! @ # $ % ^ & * ( ) _ + - = [ ] { } | '
•
•	Enable password expiration – You can select and specify a minimum of 1 and a maximum of 1,095 days that IAM user passwords are valid after they are set. For example, after 90 days a user's password expires and they must set a new password before accessing the AWS Management Console. The AWS Management Console warns IAM users when they are within 15 days of password expiration. IAM users can change their password at any time if they have permission. When they set a new password, the expiration period for that password starts over. An IAM user can have only one valid password at a time.
•	Password expiration requires administrator reset – Select this option to prevent IAM users from updating their own passwords after the password expires. Before you select this option, confirm that your AWS account has more than one user with administrative permissions to reset IAM user passwords. Also consider providing access keys to allow administrators to reset IAM user passwords programmatically. If you clear this check box, IAM users with expired passwords must still set a new password before they can access the AWS Management Console.
•	Allow users to change their own password – You can permit all IAM users in your account to use the IAM console to change their own passwords, as described in Permitting IAM users to change their own passwords. Alternatively, you can allow only some users to manage passwords, either for themselves or for others. To do so, you clear this check box. For more information about using policies to limit who can manage passwords, see Permitting IAM users to change their own passwords.
•	Prevent password reuse – You can prevent IAM users from reusing a specified number of previous passwords. You can specify a minimum number of 1 and a maximum number of 24 previous passwords that can't be repeated.

[default]
aws_access_key_id={YOUR_ACCESS_KEY_ID}
aws_secret_access_key={YOUR_SECRET_ACCESS_KEY}

[profile2]
aws_access_key_id={YOUR_ACCESS_KEY_ID}
aws_secret_access_key={YOUR_SECRET_ACCESS_KEY}

`;

const HEX_ONLY_DATAS: { [msg: string]: string } = {
    'DATA_ONLY_A': DATA_ONLY_A,
    'DATA_ONLY_HEX': DATA_ONLY_HEX,
}
const SIMPLE_DATAS: { [msg: string]: string } = {
    'DATA_ONLY_ALPHAS': DATA_ONLY_ALPHAS,
    'DATA_WITH_SPACES': DATA_WITH_SPACES,
}
const COMPLEX_DATAS: { [msg: string]: string } = {
    'DATA_WITH_SPACES_AND_SOME_CHARS': DATA_WITH_SPACES_AND_SOME_CHARS,
    'DATA_WITH_SPACES_AND_SOME_CHARS_NEW_LINES': DATA_WITH_SPACES_AND_SOME_CHARS_NEW_LINES,
    'DATA_WITH_AWS_CREDENTIALS_ENTIRE_PARAGRAPH': DATA_WITH_AWS_CREDENTIALS_ENTIRE_PARAGRAPH,
}
const DATAS: { [msg: string]: string } = {
    ...HEX_ONLY_DATAS,
    ...SIMPLE_DATAS,
    ...COMPLEX_DATAS,
}

const HEX_CHARACTERS = '0123456789abcdef';

describe(`when encoding string to hex string`, () => {
    Object.keys(DATAS).forEach(msg => {
        describe(`with ${msg}`, () => {
            const data = DATAS[msg];

            it(`should not error`, async () => {
                let hexString = await encodeStringToHexString(data);
                expect(hexString).toBeTruthy();
            });

            it(`should convert back to original string from hex`, async () => {
                let hexString = await encodeStringToHexString(data);
                expect(hexString).toBeTruthy();

                let data2 = await decodeHexStringToString(hexString);
                expect(data2).toEqual(data);
                // just to look at the data
                // console.log(`data: ${data}`);
                // console.log(`hexString: ${hexString}`);
                // console.log(`data2: ${data2}`)
                // console.log('');
            });

            it(`should only contain hex chars in string ${HEX_CHARACTERS}`, async () => {
                let hexString = await encodeStringToHexString(data);
                for (let i = 0; i < hexString.length; i++) {
                    let char = hexString.charAt(i);
                    expect(HEX_CHARACTERS).toContain(char);
                }
            });
        });
    });
    Object.keys(HEX_ONLY_DATAS).forEach(msg => {
        describe(`with ${msg}`, () => {
            const data = HEX_ONLY_DATAS[msg];

            it(`hex string should NOT be equal to original string, even though original had "hex" characters only`, async () => {
                let hexString = await encodeStringToHexString(data);
                expect(hexString).not.toEqual(data);
            });
        });
    });

    Object.keys(SIMPLE_DATAS).forEach(msg => {
        describe(`with ${msg}`, () => {
            const data = SIMPLE_DATAS[msg];

            it(`hex string should NOT be equal to original string`, async () => {
                let hexString = await encodeStringToHexString(data);
                expect(hexString).not.toEqual(data);
            });
        });
    });

});
