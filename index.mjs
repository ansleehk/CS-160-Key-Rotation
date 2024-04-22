import { randomBytes } from 'crypto';
import { SecretsManagerClient, UpdateSecretCommand, UpdateSecretVersionStageCommand, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";


export async function handler(event) {
    const secretId = event.SecretId; // The secret ARN or name; passed in via the event when invoked by Secrets Manager

    try {
        // Generate a new HMAC key
        const newHMACKey = randomBytes(32).toString('hex'); // 256-bit key

        // Get the previous secret version
        const previousVersionId = await getPreviousSecret(secretId);

        // Update the secret with the new HMAC key
        const updateReq = await updateSecret(secretId, newHMACKey);

        // Update the secret version stage
        const newVersionId = updateReq.VersionId;
        await updateSecretVersionStage(secretId, previousVersionId, newVersionId);

        console.log(`Successfully rotated HMAC key for secret: ${secretId}`);
    } catch (error) {
        console.error(`Error rotating HMAC key for secret: ${secretId}`);
        throw error;
    }
};

async function getPreviousSecret(secretId) {
    const client = new SecretsManagerClient({ region: process.env["AWS_SECRET_REGION"] });

    // Get the secret value
    const getSecretValueCommand = new GetSecretValueCommand({
        SecretId: secretId,
        VersionStage: 'AWSCURRENT',
    });

    const response = await client.send(getSecretValueCommand);

    return response.VersionId;

}

async function updateSecret(secretId, newHMACKey) {
    const client = new SecretsManagerClient({ region: process.env["AWS_SECRET_REGION"] });

    // Update the secret with the new HMAC key
    const updateSecretCommand = new UpdateSecretCommand({
        SecretId: secretId,
        SecretString: newHMACKey,
    });

    const response = await client.send(updateSecretCommand);

    return response;
}

async function updateSecretVersionStage(secretId, oldVersionId, newVersionId) {
    const client = new SecretsManagerClient({ region: process.env["AWS_SECRET_REGION"] });

    // Update the secret version stage
    const updateSecretVersionStageCommand = new UpdateSecretVersionStageCommand({
        SecretId: secretId,
        VersionStage: 'AWSCURRENT',
        MoveToVersionId: newVersionId,
        RemoveFromVersionId: oldVersionId
    });

    await client.send(updateSecretVersionStageCommand);
}
