import { Injectable } from '@nestjs/common';
import axios from 'axios';
import * as url from 'url';

@Injectable()
export class CloudProvidersMetaData {
  public static readonly GOOGLE: string =
    'http://metadata.google.internal/computeMetadata/v1/';
  public static readonly AZURE: string =
    'http://169.254.169.254/metadata/instance';
  public static readonly DIGITAL_OCEAN: string =
    'http://169.254.169.254/metadata/v1';
  public static readonly DIGITAL_OCEAN_JSON: string =
    'http://169.254.169.254/metadata/v1.json';
  public static readonly AWS: string =
    'http://169.254.169.254/latest/meta-data/';

  private providers: Map<string, string> = new Map<string, string>();

  constructor() {
    this.providers.set(
      CloudProvidersMetaData.GOOGLE,
      `
        instance/
        oslogin/
        project/
    `.trim()
    );
    this.providers.set(
      CloudProvidersMetaData.DIGITAL_OCEAN,
      `
        id
        hostname
        user-data
        vendor-data
        public-keys
        region
        interfaces/
        dns/
        floating_ip/
        reserved_ip/
        tags/
        features/
    `.trim()
    );
    this.providers.set(
      CloudProvidersMetaData.AZURE,
      `
        compute/
        network/
    `.trim()
    );
    this.providers.set(
      CloudProvidersMetaData.AWS,
      `
        ami-id
        ami-launch-index
        ami-manifest-path
        block-device-mapping/
        events/
        hostname
        iam/
        instance-action
        instance-id
        instance-life-cycle
        instance-type
        local-hostname
        local-ipv4
        mac
        metrics/
        network/
        placement/
        profile
        public-hostname
        public-ipv4
        public-keys/
        reservation-id
        security-groups
        services/
    `.trim()
    );
  }

  async get(providerUrl: string): Promise<string> {
    const parsedUrl = new url.URL(providerUrl);
    const allowedHosts = [
      'metadata.google.internal',
      '169.254.169.254',
    ];

    if (!allowedHosts.includes(parsedUrl.hostname)) {
      throw new Error(`Access to the host '${parsedUrl.hostname}' is not allowed.`);
    }

    if (providerUrl.startsWith(CloudProvidersMetaData.GOOGLE)) {
      return this.providers.get(CloudProvidersMetaData.GOOGLE);
    } else if (providerUrl.startsWith(CloudProvidersMetaData.DIGITAL_OCEAN)) {
      return this.providers.get(CloudProvidersMetaData.DIGITAL_OCEAN);
    } else if (providerUrl.startsWith(CloudProvidersMetaData.AWS)) {
      return this.providers.get(CloudProvidersMetaData.AWS);
    } else if (providerUrl.startsWith(CloudProvidersMetaData.AZURE)) {
      return this.providers.get(CloudProvidersMetaData.AZURE);
    } else {
      throw new Error('Access to the specified URL is not permitted.');
    }
  }
}