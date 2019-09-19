package util

import (
	certificates "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateSigningRequestInterface is a subset of certificate.CertificateSigningRequestInterface
type CertificateSigningRequestInterface interface {
	Create(*certificates.CertificateSigningRequest) (*certificates.CertificateSigningRequest, error)
	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*certificates.CertificateSigningRequest, error)
	UpdateApproval(*certificates.CertificateSigningRequest) (*certificates.CertificateSigningRequest, error)
}
