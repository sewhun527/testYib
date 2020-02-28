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



============================
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


#####$$$$$$$$$$$$






package org.soitoolkit.commons.mule.zip;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;
import org.mule.api.MuleMessage;
import org.mule.api.transformer.TransformerException;
import org.mule.config.i18n.MessageFactory;
import org.mule.routing.filters.WildcardFilter;
import org.mule.transformer.AbstractMessageTransformer;
import org.mule.transport.file.FileConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UnzipTransformer extends AbstractMessageTransformer {

	static final Logger log = LoggerFactory.getLogger(UnzipTransformer.class);
	
	public static final String FILE_CONTENT = "content";
	public static final String FILE_NAME = "fileName";
	
	private WildcardFilter filter = new WildcardFilter("*");

	
	public void setFilenamePattern(String pattern) {
		filter.setPattern(pattern);
	}

	
	public String getFilenamePattern() {
		return filter.getPattern();
	}
	
	
	@Override
	public Object transformMessage(MuleMessage message, String outputEncoding) throws TransformerException {
		Object payload = message.getPayload();

		InputStream is = null;
		if (payload instanceof InputStream) {
			is = (InputStream)payload;

		} else if (payload instanceof byte[]) {
			is = new ByteArrayInputStream((byte[]) payload);

		} else {
			throw new RuntimeException("Unknown payload type: " + payload.getClass().getName());
		}

		ZipInputStream zis = new ZipInputStream(is);
		ZipEntry entry = null;
		List<Map<String, String>> results = new ArrayList<Map<String, String>>();
		try {
			while ((entry = zis.getNextEntry()) != null) {
				
				String name = entry.getName();

			
				if (entry.isDirectory()) {
					log.debug("skip folder " + name);
					continue;
				}

				
				if (!filter.accept(name)) {
					log.debug("skip file " + name + " did not match filename pattern: " + filter.getPattern());
					continue;
				}

				int lastDirSep = name.lastIndexOf('/');
				if (lastDirSep != -1) {
					log.debug("unzip strips zip-folderpath " + name.substring(0, lastDirSep));
					name = name.substring(lastDirSep + 1);
				}
				if (log.isDebugEnabled()) {
					Object oldname = message.getInboundProperty(FileConnector.PROPERTY_ORIGINAL_FILENAME);
					log.debug("unzip replaces original filename " + oldname + " with " + name);
				}
				
				StringWriter writer = new StringWriter();
				IOUtils.copy(new BufferedInputStream(zis), writer, encoding);
				
				Map<String, String> fileEntry = new HashMap<String, String>();
				fileEntry.put(FILE_NAME, name);
				fileEntry.put(FILE_CONTENT, writer.toString());
				
				results.add(fileEntry);
			}
		} 
		catch (IOException ioException) {
			throw new TransformerException(MessageFactory.createStaticMessage("Failed to uncompress file."), this, ioException);
		}
		return results;
	}
}




