/* eslint-disable */
'use strict';

const SecretManagerServiceClient = require('@google-cloud/secret-manager').SecretManagerServiceClient;

function secretPathFor(project, id) {
    return `projects/${project}/secrets/${id}/versions/latest`
}

class GCPSecretReader {
    /**
     * Creates an instance of the gcp secret reader
     * @param {string} project gcp project the secrets are stored in
     */
    constructor(project) {
        this.secrets = new SecretManagerServiceClient();
        this.project = project
    }
    /**
     * @param {name} the name of the secret
     * @returns binary encoded secret data
     */
    static async read(id) {
        const path = secretPathFor(id);
        const [version] = await this.secrets.accessSecretVersion({name: path});
        return version.payload.data;
    }
}

export default GCPSecretReader;