import { Rule, FileType } from '@/types/scanner';
import { terraformPublicS3Rule } from './terraform/publicS3';
import { terraformAwsSecurityRules } from './terraform/awsSecurity';
import { terraformAwsIAMRules } from './terraform/awsIAM';
import { terraformAwsPrivilegeEscalationRules } from './terraform/awsPrivilegeEscalation';
import { terraformAwsCriticalSecurityRules } from './terraform/awsCriticalSecurity';
import { terraformTfsecRules } from './terraform/awsTfsecRules';
import { terraformAdditionalServicesRules } from './terraform/awsAdditionalServices';
import { terraformAwsLambdaRules } from './terraform/awsLambda';
import { terraformAwsLoggingRules } from './terraform/awsLogging';
import { terraformAwsBackupRules } from './terraform/awsBackup';
import { terraformSecretScanningRules } from './terraform/secretScanning';
import { terraformLowSeverityRules } from './terraform/lowSeverityRules';
import { terraformAwsMessagingRules } from './terraform/awsMessaging';
import { terraformAwsApiGatewayRules } from './terraform/awsApiGateway';
import { terraformAwsStepFunctionsRules } from './terraform/awsStepFunctions';
import { terraformAwsEKSRules } from './terraform/awsEKS';
import { terraformAwsECRRules } from './terraform/awsECR';
import { kubernetesRunAsRootRule } from './kubernetes/runAsRoot';
import { kubernetesSecurityContextRules } from './kubernetes/securityContext';
import { kubernetesSecretsRule } from './kubernetes/secrets';
import { kubernetesImageSecurityRules } from './kubernetes/imageSecurity';
import { kubernetesResourceLimitsRules } from './kubernetes/resourceLimits';
import { kubernetesNetworkSecurityRules } from './kubernetes/networkSecurity';
import { kubernetesCapabilitiesRules } from './kubernetes/capabilities';
import { kubernetesVolumesRules } from './kubernetes/volumes';
import { kubernetesSecretScanningRules } from './kubernetes/secretScanning';
import { kubernetesLowSeverityRules } from './kubernetes/lowSeverityRules';
import { dockerfileLatestTagRule } from './dockerfile/latestTag';
import { dockerfileRootUserRule } from './dockerfile/rootUser';
import { dockerfileExposePort22Rule } from './dockerfile/exposePort22';
import { dockerfileSecurityRules } from './dockerfile/security';
import { dockerfileAdditionalSecurityRules } from './dockerfile/additionalSecurity';
import { dockerfileLowSeverityRules } from './dockerfile/lowSeverityRules';
import { dockerComposeSecurityRules } from './docker-compose/privileged';
import { dockerComposeLowSeverityRules } from './docker-compose/lowSeverityRules';
import { yamlPlaceholderRule } from './yaml/placeholder';
import { jsonPlaceholderRule } from './json/placeholder';
import { cloudformationAwsSecurityRules, cloudformationAwsNetworkRules, cloudformationAwsIAMRules, cloudformationAwsLoggingRules, cloudformationAwsBackupRules } from './cloudformation/awsSecurity';
import { cloudformationSecretScanningRules } from './cloudformation/secretScanning';

export const ruleRegistry: Rule[] = [
  // Terraform rules
  terraformPublicS3Rule,
  ...terraformAwsSecurityRules,
  ...terraformAwsIAMRules,
  ...terraformAwsPrivilegeEscalationRules,
  ...terraformAwsCriticalSecurityRules,
  ...terraformTfsecRules,
  ...terraformAdditionalServicesRules,
  ...terraformAwsLambdaRules,
  ...terraformAwsLoggingRules,
  ...terraformAwsBackupRules,
  ...terraformSecretScanningRules,
  ...terraformLowSeverityRules,
  ...terraformAwsMessagingRules,
  ...terraformAwsApiGatewayRules,
  ...terraformAwsStepFunctionsRules,
  ...terraformAwsEKSRules,
  ...terraformAwsECRRules,

  // Kubernetes rules
  kubernetesRunAsRootRule,
  ...kubernetesSecurityContextRules,
  kubernetesSecretsRule,
  ...kubernetesImageSecurityRules,
  ...kubernetesResourceLimitsRules,
  ...kubernetesNetworkSecurityRules,
  ...kubernetesCapabilitiesRules,
  ...kubernetesVolumesRules,
  ...kubernetesSecretScanningRules,
  ...kubernetesLowSeverityRules,
  
  // Dockerfile rules
  dockerfileLatestTagRule,
  dockerfileRootUserRule,
  dockerfileExposePort22Rule,
  ...dockerfileSecurityRules,
  ...dockerfileAdditionalSecurityRules,
  ...dockerfileLowSeverityRules,
  
  // Docker Compose rules
  ...dockerComposeSecurityRules,
  ...dockerComposeLowSeverityRules,
  
  // Placeholder rules
  yamlPlaceholderRule,
  jsonPlaceholderRule,
  
  // CloudFormation rules
  ...cloudformationAwsSecurityRules,
  ...cloudformationAwsNetworkRules,
  ...cloudformationAwsIAMRules,
  ...cloudformationAwsLoggingRules,
  ...cloudformationAwsBackupRules,
  ...cloudformationSecretScanningRules,
];

export function getRulesForFileType(fileType: string): Rule[] {
  return ruleRegistry.filter(rule => 
    rule.applicableFileTypes.includes(fileType as FileType)
  );
}
