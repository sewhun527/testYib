<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <soapenv:Body>
  <notifications xmlns="http://soap.sforce.com/2005/09/outbound">
   <OrganizationId>00DV0000008s2SrMAI</OrganizationId>
   <ActionId>04k460000004DXEAA2</ActionId>
   <SessionId xsi:nil="true"/>
   <EnterpriseUrl>https://cce2e--IntDevD.my.salesforce.com/services/Soap/c/39.0/00DV0000008s2Sr</EnterpriseUrl>
   <PartnerUrl>https://cce2e--IntDevD.my.salesforce.com/services/Soap/u/39.0/00DV0000008s2Sr</PartnerUrl>
   <Notification>
    <Id>04lV000000nKC8cIAG</Id>
    <sObject xmlns:sf="urn:sobject.enterprise.soap.sforce.com" xsi:type="sf:IntegrationMessage__c">
     <sf:Id>a4xV0000002ykKIIAY</sf:Id>
     <sf:CreatedDate>2019-10-24T14:25:43.000Z</sf:CreatedDate>
     <sf:EventDetail__c>NewLoan</sf:EventDetail__c>
     <sf:Event__c>PipelineBooking</sf:Event__c>
     <sf:LastModifiedDate>2019-10-24T14:25:43.000Z</sf:LastModifiedDate>
     <sf:MessageNumber__c>IM-0000120593</sf:MessageNumber__c>
     <sf:ObjectID__c>a0iV0000002TKEqIAO</sf:ObjectID__c>
     <sf:ObjectName__c>LLC_BI__Loan__c</sf:ObjectName__c>
     <sf:Record_Name__c>USD202.0K CS R/E Balloon Term</sf:Record_Name__c>
     <sf:Status__c>NEW</sf:Status__c>
     <sf:XBOAPassword__c>subhod2p</sf:XBOAPassword__c>
     <sf:XBOAUserID__c>xxxxxxx</sf:XBOAUserID__c>
     <sf:boaUserId__c>yyyyyyyyy</sf:boaUserId__c>
    </sObject>
   </Notification>
  </notifications>
 </soapenv:Body>
</soapenv:Envelope>
=======================================
%dw 1.0
%output application/java
%namespace ns0 http://schemas.xmlsoap.org/soap/envelope/
%namespace ns1 http://soap.sforce.com/2005/09/outbound
%namespace ns2 urn:sobject.enterprise.soap.sforce.com
---
{
	ns0#Envelope: {
		ns0#Body: {
			ns1#notifications: {
				ns1#Notification: {
					ns1#sObject: {
						ns2#Id: payload.ns0#Envelope.ns0#Body.ns1#notifications.ns1#Notification.ns1#sObject.ns2#Id,
						ns2#XBOAPassword: payload.ns0#Envelope.ns0#Body.ns1#notifications.ns1#Notification.ns1#sObject.ns2#XBOAPassword__c,
						ns2#XBOAUserid: payload.ns0#Envelope.ns0#Body.ns1#notifications.ns1#Notification.ns1#sObject.ns2#XBOAUserID__c,
						ns2#boaUserid: payload.ns0#Envelope.ns0#Body.ns1#notifications.ns1#Notification.ns1#sObject.ns2#boaUserId__c
					}
				}
			}
		}
	}
}

=======================================
%dw 1.0
%output application/java
---
payload.Envelope.Body.notifications.Notification.sObject.XBOAUserID__c
