<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
	xmlns:metadata="http://www.mulesoft.org/schema/mule/metadata" xmlns:db="http://www.mulesoft.org/schema/mule/db"
	xmlns:json="http://www.mulesoft.org/schema/mule/json"
	xmlns:scripting="http://www.mulesoft.org/schema/mule/scripting"
	xmlns:tracking="http://www.mulesoft.org/schema/mule/ee/tracking" xmlns:validation="http://www.mulesoft.org/schema/mule/validation"
	xmlns:ws="http://www.mulesoft.org/schema/mule/ws"
	xmlns:dw="http://www.mulesoft.org/schema/mule/ee/dw"
	xmlns:context="http://www.springframework.org/schema/context" xmlns:doc="http://www.mulesoft.org/schema/mule/documentation" xmlns:tls="http://www.mulesoft.org/schema/mule/tls" xmlns:spring="http://www.springframework.org/schema/beans" xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:api-platform-gw="http://www.mulesoft.org/schema/mule/api-platform-gw"
      xmlns:expression-language="http://www.mulesoft.org/schema/mule/expression-language-gw"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.mulesoft.org/schema/mule/ee/core http://www.mulesoft.org/schema/mule/ee/core/current/mule-ee.xsd
http://www.mulesoft.org/schema/mule/db http://www.mulesoft.org/schema/mule/db/current/mule-db.xsd
http://www.mulesoft.org/schema/mule/json http://www.mulesoft.org/schema/mule/json/current/mule-json.xsd
http://www.mulesoft.org/schema/mule/scripting http://www.mulesoft.org/schema/mule/scripting/current/mule-scripting.xsd
http://www.mulesoft.org/schema/mule/validation http://www.mulesoft.org/schema/mule/validation/current/mule-validation.xsd
http://www.mulesoft.org/schema/mule/ws http://www.mulesoft.org/schema/mule/ws/current/mule-ws.xsd
http://www.mulesoft.org/schema/mule/ee/dw http://www.mulesoft.org/schema/mule/ee/dw/current/dw.xsd
http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
http://www.mulesoft.org/schema/mule/http http://www.mulesoft.org/schema/mule/http/current/mule-http.xsd
http://www.mulesoft.org/schema/mule/api-platform-gw http://www.mulesoft.org/schema/mule/api-platform-gw/current/mule-api-platform-gw.xsd
http://www.mulesoft.org/schema/mule/expression-language-gw http://www.mulesoft.org/schema/mule/expression-language-gw/current/mule-expression-language-gw.xsd
http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-current.xsd
http://www.mulesoft.org/schema/mule/tls http://www.mulesoft.org/schema/mule/tls/current/mule-tls.xsd
http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context-current.xsd
http://www.mulesoft.org/schema/mule/ee/tracking http://www.mulesoft.org/schema/mule/ee/tracking/current/mule-tracking-ee.xsd">

    <configuration defaultProcessingStrategy="non-blocking" doc:name="Configuration"/>
    
    <context:property-placeholder location="config-${env}.properties"/>

    <expression-language:property-placeholder location="config-${env}.properties"/>
    
    <http:request-config
      name="http-request-config"
      host="#[flowVars.hostname]"
      port="#[flowVars.portno]"
      basePath="${implementation.path}"
      protocol="HTTPS" doc:name="HTTPS Request Configuration" responseTimeout="300000" enableCookies="true" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>
    
    <http:listener-config name="HTTPS_Listener_Configuration" protocol="HTTPS" host="![p['proxy.host']]" port="![p['proxy.port']]" doc:name="HTTPS Listener Configuration" connectionIdleTimeout="300000">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:listener-config>
    
    <http:request-config name="HTTP_Request_Configuration" host="#[flowVars.headersandprops.props.Target_Host]" port="#[flowVars.headersandprops.props.Target_Port_Number]" doc:name="HTTP Request Configuration" responseTimeout="120000" enableCookies="true" usePersistentConnections="false"/>
    
	<custom-transformer class="com.bofa.transformer.CookieFetching" name="MyCookieTranformer" doc:name="Java"/>
	
    <validation:config name="Validation_Configuration" doc:name="Validation Configuration"/>
    
    <ee:object-store-caching-strategy name="Caching_Strategy" doc:name="Caching Strategy">
        <managed-store storeName="globalCachingStrategy" maxEntries="${caching.strategy.maxentries}" entryTTL="${caching.strategy.entryttl}" expirationInterval="300000"/>
    </ee:object-store-caching-strategy>
    
    <http:request-config name="HTTPS_Request_Configuration_GW" protocol="HTTPS" host="${api.host}" port="${api.port}" basePath="/b2biportal/api" doc:name="HTTPS Request Configuration"   responseTimeout="600000" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>    
    
    <http:request-config name="HTTPS_Request_Configuration_Monitor" protocol="HTTPS" host="${api.host}" port="${api.port}" basePath="/monitor" doc:name="HTTPS Request Configuration" enableCookies="true"  responseTimeout="600000" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>
    
    <http:request-config name="HTTPS_Request_Configuration_1" host="#[flowVars.headersandprops.props.Target_Host]" port="#[flowVars.headersandprops.props.Target_Port_Number]" doc:name="HTTPS Request Configuration"  responseTimeout="1200000" parseResponse="false" protocol="HTTPS" enableCookies="true" followRedirects="false" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store path="${truststore.path}" password="${truststore.password}" insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>
    
    <http:request-config name="HTTPS_Request_Configuration_2" protocol="HTTPS" host="#[flowVars.headersandprops.props.Target_Host]" port="#[flowVars.headersandprops.props.Target_Port_Number]" doc:name="HTTPS Request Configuration"  responseTimeout="120000" enableCookies="true" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>
        
    <http:request-config name="HTTPS_Request_Configuration_OAuth2" protocol="HTTPS" host="#[flowVars.headersandprops.props.OAuth_Token_Server_Host]" port="#[flowVars.headersandprops.props.OAuth_Token_Server_Port]" doc:name="HTTPS Request Configuration"  responseTimeout="120000" enableCookies="true" usePersistentConnections="false">
        <tls:context enabledProtocols="TLSv1.2">
            <tls:trust-store insecure="true"/>
            <tls:key-store type="pkcs12" path="${keystore.path}" keyPassword="${keystore.password}" password="${keystore.password}"/>
        </tls:context>
    </http:request-config>
    <http:request-config name="HTTP_OAuth_Checker_Service" protocol="HTTPS" host="${oauth.checker.service.host}" port="${oauth.checker.service.port}" basePath="${oauth.checker.service.basepath}" doc:name="HTTP Request Configuration"/>        
    
    <flow name="Gateway_Validations" processingStrategy="non-blocking">
        <http:listener config-ref="HTTPS_Listener_Configuration" path="![p['proxy.path']]" parseRequest="false" doc:name="HTTPS"/>
        <object-to-byte-array-transformer doc:name="Object to Byte Array"/>
        <set-variable variableName="traceId" value="#[java.util.UUID.randomUUID().toString()]" doc:name="Trace Id"/>
        <!-- <copy-properties propertyName="*" doc:name="Copy All Inbound Properties"/> -->
        <logger message="&lt;------ Trace ID : '#[flowVars.traceId]' ------- PZ : Gateway Validations Inbound Properties ---------&gt; '#[message.inboundProperties]'" level="INFO" doc:name="Logger"/>
        <message-properties-transformer doc:name="Message Properties">
            <add-message-property key="X-BOA-B2BI-ClientID" value="#[message.inboundProperties.'X-BOA-B2BI-ClientID' != null &amp;&amp; message.inboundProperties.'X-BOA-B2BI-ClientID' != empty ? message.inboundProperties.'X-BOA-B2BI-ClientID' : message.inboundProperties.'http.request.uri'.split('/')[1]]"/>
            <add-message-property key="X-BOA-B2BI-TraceID" value="#[flowVars.traceId]"/>
            <add-message-property key="NODE_NAME" value="${node.name}"/>
            <add-message-property key="DIRECTION" value="${direction}"/>
            <add-message-property key="X-FORWARDED-FOR" value="#[message.inboundProperties.'x-forwarded-for']"/>
            <add-message-property key="X-BOA-B2BI-Token" value="#[message.inboundProperties.'X-BOA-B2BI-Token']"/>
        </message-properties-transformer>        
        <enricher   doc:name="Message Enricher">
            <flow-ref name="Validations_Flow" doc:name="Validations_Flow"/>
            <enrich source="#[message.payloadAs(java.lang.String)]" target="#[flowVars.responsePayload]"/>
            <enrich source="#[message.inboundProperties.'http.status']" target="#[flowVars.responseStatus]"/>
            <enrich source="#[message.inboundProperties.'host']" target="#[flowVars.hostname]"/>
            <enrich source="#[message.inboundProperties.'port']" target="#[flowVars.portno]"/>
            <enrich source="#[message.inboundProperties.'pingoauth']" target="#[flowVars.pingoauth]"/>
            <enrich source="#[message.inboundProperties.'tokengeneration']" target="#[flowVars.tokengeneration]"/>
            <enrich source="#[message.inboundProperties.'oauthclientid']" target="#[flowVars.oauthclientid]"/>
        </enricher>
        <validation:is-true config-ref="Validation_Configuration" exceptionClass="java.lang.IllegalArgumentException" expression="#[flowVars.responseStatus != null &amp;&amp; flowVars.responseStatus.toString() == '200']" doc:name="Validation"/>
        <enricher doc:name="Message Enricher">
            <flow-ref name="IAM_OAuth_Flow" doc:name="IAM_OAuth_Flow"/>
            <enrich source="#[message.payloadAs(java.lang.String)]" target="#[flowVars.responsePayload]"/>
            <enrich source="#[message.inboundProperties.'http.status' != null ? message.inboundProperties.'http.status' : message.outboundProperties.'http.status']" target="#[flowVars.responseStatus]"/>
            <enrich source="#[message.inboundProperties.'authorization']" target="#[flowVars.oauthtoken]"/>
        </enricher>
        <validation:is-true config-ref="Validation_Configuration" exceptionClass="java.lang.IllegalArgumentException" expression="#[flowVars.responseStatus != null &amp;&amp; flowVars.responseStatus.toString() == '200']" doc:name="Validation"/>
        <choice doc:name="Choice">
            <when expression="#[flowVars.oauthtoken != null &amp;&amp; flowVars.oauthtoken != empty]">
                <message-properties-transformer doc:name="Message Properties">
                	<add-message-property key="Authorization" value="#['Bearer ' + flowVars.oauthtoken]"/>
                	<add-message-property key="X-BOA-B2BI-Authentication" value="#[flowVars.oauthtoken]"/>
                </message-properties-transformer>
            </when>
            <otherwise>
                <logger message="&lt;----- Trace ID : '#[message.outboundProperties.'X-BOA-B2BI-TraceID']' ----- oAuth token generation is disabled ----&gt;" level="INFO" doc:name="Logger"/>
            </otherwise>
        </choice>
        <choice doc:name="Choice">
            <when expression="#[message.outboundProperties['X-BOA-B2BI-ClientID'].contains('attorney') || message.outboundProperties['X-BOA-B2BI-ClientID'].contains('Attorney')]">
                <enricher doc:name="Message Enricher">
                    <flow-ref name="AV_Scan_Flow" doc:name="AV_Scan_Flow"/>
                    <enrich source="#[payload]" target="#[flowVars.responsePayload]"/>
                    <enrich source="#[message.inboundProperties.'http.status' != null ? message.inboundProperties.'http.status' : message.outboundProperties.'http.status']" target="#[flowVars.responseStatus]"/>
                </enricher>
                <validation:is-true config-ref="Validation_Configuration" exceptionClass="java.lang.IllegalArgumentException" expression="#[flowVars.responseStatus != null &amp;&amp; flowVars.responseStatus.toString() == '200']" doc:name="Validation"/>
            </when>
            <otherwise>
                <logger message="&lt;----- Trace ID : '#[message.outboundProperties.'X-BOA-B2BI-TraceID']' ---- Skipping Virus Scan ----&gt;" level="INFO" doc:name="Logger"/>
            </otherwise>
        </choice>
        <copy-properties propertyName="*" doc:name="Copy All Inbound Properties"/>
        <logger message="&lt;------ Trace ID : '#[flowVars.traceId]' ------- PZ : Gateway Validations Outbound Properties ---------&gt; '#[message.outboundProperties]'" level="INFO" doc:name="Logger"/>
		<http:request config-ref="http-request-config" method="#[message.inboundProperties.'http.method']" path="#[message.inboundProperties.'http.request.uri']" doc:name="HTTPS Requester" followRedirects="false">
			<http:success-status-code-validator values="0..599" />
		</http:request>
		<copy-properties propertyName="*" doc:name="Copy All Inbound Properties"/>
        <logger message="&lt;------ Trace ID : '#[flowVars.traceId]' -------  Routing Response ---------&gt; '#[message.outboundProperties]'" level="INFO" doc:name="Logger"/>
        <exception-strategy ref="GatewayValidationsChoiceExceptionStrategy" doc:name="Reference Exception Strategy"/>
    </flow>
    
    <sub-flow name="Validations_Flow">
    	<transformer ref="MyCookieTranformer" doc:name="Transformer Reference"/>
        <message-properties-transformer doc:name="Message Properties">
            <delete-message-property key="Authorization"/>
            <delete-message-property key="Accept"/>
        </message-properties-transformer>
    	<message-properties-transformer doc:name="Message Properties">
            <add-message-property key="Authorization" value="${Authorization}"/>
            <add-message-property key="GW_OPEARTION_TYPE" value="POLICY"/>
            <add-message-property key="GW_OPEARTION" value="Authentication"/>            
            <add-message-property key="METHOD" value="#[message.inboundProperties.'http.method']"/>
        </message-properties-transformer>
        <http:request config-ref="HTTPS_Request_Configuration_GW" path="/b2bi-api-gateway/authenticate" method="GET" followRedirects="false" doc:name="GatewayValidation">
            <http:request-builder>
                <http:header headerName="B2BI-SMSESSION" value="#[message.outboundProperties.'B2BI-SMSESSION']"/>
            </http:request-builder>
        	<http:success-status-code-validator values="0..599" />
        </http:request>
        <remove-property propertyName="B2BI-SMSESSION" doc:name="Property"/>
    </sub-flow>
    
    <sub-flow name="IAM_OAuth_Flow">
        <choice doc:name="Choice">
            <when expression="#[flowVars.pingoauth == 'YES']">
                <message-properties-transformer doc:name="Message Properties">
                    <add-message-property key="Authorization" value="${Authorization}"/>                    
                </message-properties-transformer>
                <set-payload value="{
	&quot;xboab2biclientid&quot;: &quot;#[message.outboundProperties.'X-BOA-B2BI-ClientID']&quot;,
	&quot;xboab2bitoken&quot;: &quot;#[message.outboundProperties.'X-BOA-B2BI-Token']&quot;,
	&quot;tokengeneration&quot;: &quot;#[flowVars.tokengeneration]&quot;,
	&quot;oauthclientid&quot;: &quot;#[flowVars.oauthclientid]&quot;
}" doc:name="Set Payload" mimeType="application/json"/>
                <ee:cache doc:name="Cache" cachingStrategy-ref="Caching_Strategy">
                    <http:request config-ref="HTTPS_Request_Configuration_GW" path="/b2bi-api-gateway/oauthservice" method="POST" followRedirects="false" doc:name="IAM OAuth Service">
                        <http:success-status-code-validator values="0..599"/>
                    </http:request>
                    <set-variable variableName="tokenStatusCode" value="#[message.inboundProperties.'http.status']" doc:name="Set tokenStatusCode Variable"/>
                    <enricher source="payload" target="flowVars.oauthTriggerResponse" doc:name="Message Enricher">
                        <flow-ref name="Check_OAuth_Response_Flow" doc:name="Check_OAuth_Response_Flow"/>
                    </enricher>
                    <object-to-string-transformer doc:name="Object to String"/>
                </ee:cache>
            </when>
            <otherwise>
                <set-payload value="{
    &quot;message&quot;: &quot;oAuth not enabled for this client.&quot;,
    &quot;status&quot;: &quot;VALID&quot;
}" mimeType="application/json" doc:name="Set Payload"/>
                <set-property propertyName="http.status" value="200" doc:name="Property"/>
            </otherwise>
        </choice>
    </sub-flow>
    <sub-flow name="Check_OAuth_Response_Flow">
        <choice doc:name="Choice">
            <when expression="#[flowVars.tokenStatusCode != 200]">
                <set-payload value="#['Status is not 200 for provided OAuth token']" doc:name="Set Payload"/>
            </when>
            <otherwise>
                <set-payload value="#['Status is 200 for provided OAuth token']" doc:name="Set Payload"/>
            </otherwise>
        </choice>
        <http:request config-ref="HTTP_OAuth_Checker_Service" path="${oauth.checker.service.path}" method="POST" doc:name="OAuth Checker Service">
            <http:request-builder>
                <http:header headerName="X-BOA-B2Bi-Client" value="#[message.inboundProperties.'X-BOA-B2BI-ClientID' != null &amp;&amp; message.inboundProperties.'X-BOA-B2BI-ClientID' != empty ? message.inboundProperties.'X-BOA-B2BI-ClientID' : message.inboundProperties.'http.request.uri'.split('/')[1]]"/>
                <http:header headerName="X-BOA-B2Bi-Token" value="#[message.inboundProperties.'X-BOA-B2BI-Token']"/>
            </http:request-builder>
        </http:request>
    </sub-flow>
    
    <sub-flow name="AV_Scan_Flow">
        <choice doc:name="Choice">
            <when expression="#[message.inboundProperties['http.method']== 'POST' &amp;&amp; message.inboundProperties['Content-Type'].contains('multipart/form-data')]">
                <set-attachment attachmentName="file" value="#[payload]" contentType="binary/octet-stream" doc:name="VirusScanPayload"/>
                <message-properties-transformer doc:name="Message Properties">
                    <delete-message-property key="Authorization"/>
                    <delete-message-property key="Accept"/>
                </message-properties-transformer>
                <!-- <remove-property propertyName="Authorization" doc:name="Property"/> -->
                <http:request config-ref="HTTPS_Request_Configuration_GW" path="/b2bi-api-gateway/virusscan" method="POST" doc:name="VirusScan" followRedirects="false">
                    <http:request-builder>
                        <http:header headerName="Authorization" value="${Authorization}"/>
                        <http:header headerName="GW_OPEARTION" value="DataScan"/>
                        <http:header headerName="GW_OPEARTION_TYPE" value="POLICY"/>
                        <!-- <http:header headerName="NODE_NAME" value="${node.name}"/> -->
                    </http:request-builder>
                    <http:success-status-code-validator values="0..599" />
                </http:request>                
            </when>
            <otherwise>
                <set-payload value="{&quot;status&quot;:&quot;NOSCAN&quot;,&quot;message&quot;:&quot;No scan done&quot;}" mimeType="application/json" doc:name="Set Payload"/>
                <set-property propertyName="http.status" value="200" doc:name="Property"/>
            </otherwise>
        </choice>	
    </sub-flow>
    
     <sub-flow name="Read_Headers">
        <logger message="&lt;----- Trace ID : '#[message.inboundProperties.'X-BOA-B2BI-TraceID']' ------ Mapping Value : '#[flowVars.routingVar]' --------&gt;" level="INFO" doc:name="Logger"/>
        <message-properties-transformer doc:name="Message Properties">
                    <delete-message-property key="Authorization"/>
                    <delete-message-property key="Accept"/>
                </message-properties-transformer>
        <!-- <remove-property propertyName="Authorization" doc:name="Property"/> -->
<http:request config-ref="HTTPS_Request_Configuration_GW" path="/b2bi-api-gateway/get-headers-routing" method="GET" doc:name="HTTP" followRedirects="false">
            <http:request-builder>
                <http:query-param paramName="filenameQualifier" value="#[flowVars.routingVar]"/>
                <http:header headerName="Authorization" value="${Authorization}"/>
                <http:header headerName="GW_OPEARTION_TYPE" value="TRANSPORT"/>
                <http:header headerName="GW_OPEARTION" value="Routing"/>
            </http:request-builder>
            <http:success-status-code-validator values="0..599"/>
        </http:request>
        <set-variable variableName="apiResponse" value="#[message.payloadAs(java.lang.String)]" doc:name="CopyPayload"/>
        <choice doc:name="Choice">
        <when expression="#[message.inboundProperties.'http.status' != null &amp;&amp; message.inboundProperties.'http.status'.toString() == '200']">
        	<object-to-byte-array-transformer doc:name="Object to Byte Array"/>
        <scatter-gather doc:name="Scatter-Gather">
            <dw:transform-message metadata:id="da60085e-0d6c-4fd6-92db-6b3609927293" doc:name="Transform Message">
                <dw:input-payload doc:sample="sample_data\map.dwl"/>
                <dw:set-payload><![CDATA[%dw 1.0
%output application/java
---
{
	(App_Proxy_Host: payload.routingInfo.PHost),
	(App_Proxy_Port_Number: payload.routingInfo.PPort as :string),
	(Target_Host: payload.routingInfo.THost as :string),
	(Target_Port_Number: payload.routingInfo.TPort as :string),
	(Target_URI: payload.routingInfo.TURI as :string),
	(Authentication_Type: payload.routingInfo.Authtype as :string),
	(UserName: payload.routingInfo.UserName as :string),
	(Password: payload.routingInfo.Password as :string),
	(OAuth_client_id: payload.routingInfo.Clientid as :string),
	(OAuth_client_secret: payload.routingInfo.ClientSecret as :string),
	(OAuth_Token_Server_Host: payload.routingInfo.TokenHost as :string),
	(OAuth_Token_Server_Port: payload.routingInfo.TokenPort as :string),
	(OAuth_Token_URI: payload.routingInfo.TokenURI as :string),
	(Grant_Type: payload.routingInfo.GrantType as :string),
	(API_Key: payload.routingInfo.APIKey as :string)
}]]></dw:set-payload>
            </dw:transform-message>
            <processor-chain>
                <dw:transform-message metadata:id="0ffc3392-fbdb-4268-b1d7-341f2ca433fa" doc:name="Transform Message">
                    <dw:input-payload/>
                    <dw:set-payload><![CDATA[%dw 1.0
%output application/java
---
payload.headers default [] map {
	($.key): $.value
}]]></dw:set-payload>
                </dw:transform-message>
                <component class="objectToMap.ObjectToMap" doc:name="Java"/>
            </processor-chain>
        </scatter-gather>
        <dw:transform-message doc:name="Transform Message">
            <dw:set-payload><![CDATA[%dw 1.0
%output application/java
---
{
	props:payload[0],
	headers:payload[1]	
}]]></dw:set-payload>
        </dw:transform-message>
                <set-property propertyName="http.status" value="200" doc:name="Property"/>
        </when>
            <otherwise>
                <dw:transform-message doc:name="Transform Message">
                    <dw:set-payload><![CDATA[%dw 1.0
%output application/java
---
{
	headers:'',
	props:''
}]]></dw:set-payload>
                </dw:transform-message>
            </otherwise>
        </choice>
    </sub-flow>
    
    <flow name="Gateway_Routing" processingStrategy="non-blocking">
        <http:listener config-ref="HTTPS_Listener_Configuration" path="![p['proxy.routing.path']]" doc:name="HTTPS" parseRequest="false"/>
        <logger message="&lt;----- Trace ID : '#[message.inboundProperties.'X-BOA-B2BI-TraceID']' -------- PZ : Gateway Routing Inbound Properties ---------&gt; '#[message.inboundProperties]'" level="INFO" doc:name="Logger"/>
        <set-variable variableName="routingVar" value="#[message.inboundProperties.'http.request.uri'.split('/').size() &gt; 4? '/' + message.inboundProperties.'http.request.uri'.split('/')[2] + '/' + message.inboundProperties.'http.request.uri'.split('/')[3]: message.inboundProperties.'http.request.uri'.substring(8)]" doc:name="Mapping Var"/>
		<message-properties-transformer doc:name="Message Properties">
            <add-message-property key="X-BOA-B2BI-ClientID" value="#[message.inboundProperties.'X-BOA-B2BI-ClientID']"/>
            <add-message-property key="X-BOA-B2BI-TraceID" value="#[message.inboundProperties.'X-BOA-B2BI-TraceID']"/>
            <add-message-property key="NODE_NAME" value="#[message.inboundProperties.'NODE_NAME']"/>
            <add-message-property key="DIRECTION" value="#[message.inboundProperties.'DIRECTION']"/>
        </message-properties-transformer>
        <enricher  doc:name="Message Enricher" >
            <flow-ref name="Read_Headers" doc:name="Read_Headers"/>
            <enrich source="#[payload]" target="#[flowVars.headersandprops]"/>
            <enrich source="#[flowVars.apiResponse]" target="#[flowVars.routingResponse]"/>
            <enrich source="#[message.inboundProperties.'http.status' != null ? message.inboundProperties.'http.status' : message.outboundProperties.'http.status']" target="#[flowVars.routingStatus]"/>
        </enricher>
        <validation:is-true config-ref="Validation_Configuration" exceptionClass="java.lang.IllegalArgumentException" expression="#[flowVars.routingStatus != null &amp;&amp; flowVars.routingStatus.toString() == '200']" doc:name="Validation"/>        
        <set-variable variableName="targetPath" value="#[message.inboundProperties.'http.request.path'.split('/').size() &gt; 4 ? flowVars.headersandprops.props.Target_URI + '/' + message.inboundProperties.'http.request.uri'.substring(message.inboundProperties.'http.request.path'.indexOf(message.inboundProperties.'http.request.path'.split('/')[4])) : flowVars.headersandprops.props.Target_URI]" doc:name="TargetPath"/>
        <logger message="&lt;----- Trace ID : '#[message.inboundProperties.'X-BOA-B2BI-TraceID']' ------- Target Request URI : '#[flowVars.targetPath]' -------&gt;" level="INFO" doc:name="Logger"/>
        <copy-properties propertyName="*" doc:name="Copy All Inbound Properties"/>
        <set-variable variableName="traceId" value="#[message.inboundProperties.'X-BOA-B2BI-TraceID']" doc:name="StoreTraceID"/>
		<choice doc:name="Choice">
            <when expression="#[flowVars.headersandprops.props.Authentication_Type == 'No Auth']">
                <http:request config-ref="HTTPS_Request_Configuration_1" path="#[flowVars.targetPath]" method="#[message.inboundProperties.'http.method']"  doc:name="HTTPS Requester" followRedirects="false">
                    <http:request-builder>
                        <http:headers expression="#[flowVars.headersandprops.headers]"/>
                    </http:request-builder>
                    <http:success-status-code-validator values="0..599"/>
                </http:request>
            </when>
            <when expression="#[flowVars.headersandprops.props.Authentication_Type == 'OAuth2']">
                <enricher target="#[flowVars.token]" doc:name="Message Enricher" source="#[json:access_token]">
                    <processor-chain doc:name="Processor Chain">
                        <set-variable variableName="encodedStr" value="#[flowVars.headersandprops.props.OAuth_client_id]:#[flowVars.headersandprops.props.OAuth_client_secret]" doc:name="Encoded String"/>
                        <set-payload value="grant_type=#[flowVars.headersandprops.props.Grant_Type]" doc:name="Set Payload"/>
                        <http:request config-ref="HTTPS_Request_Configuration_OAuth2" path="#[flowVars.headersandprops.props.OAuth_Token_URI]" method="POST" doc:name="HTTPS OAuth" followRedirects="false">   
                            <http:request-builder>
                                <http:header headerName="Authorization" value="#['Basic ' + new String(org.apache.commons.codec.binary.Base64.encodeBase64(flowVars.encodedStr.getBytes()))]"/>
                                <http:header headerName="Content-Type" value="application/x-www-form-urlencoded"/>
                            </http:request-builder>
                        </http:request>
                    </processor-chain>
                </enricher>
                <http:request config-ref="HTTPS_Request_Configuration_2" path="#[flowVars.targetPath]" method="#[message.inboundProperties.'http.method']" followRedirects="false" doc:name="HTTPS Requester">
                    <http:request-builder>
                        <http:header headerName="Authorization" value="#['Bearer '+flowVars.token]"/>
                        <http:headers expression="#[flowVars.headersandprops.headers]"/>
                    </http:request-builder>
                    <http:success-status-code-validator values="0..599"/>
                </http:request>
            </when>
            <when expression="#[flowVars.headersandprops.props.Authentication_Type == 'Basic']">
                <http:request config-ref="HTTP_Request_Configuration" path="#[flowVars.targetPath]" method="#[message.inboundProperties.'http.method']"  doc:name="HTTP Requester" followRedirects="false">
                    <http:request-builder>
                        <http:headers expression="#[flowVars.headersandprops.headers]"/>
                    </http:request-builder>
                    <http:success-status-code-validator values="0..599"/>
                </http:request>
            </when>
            <otherwise>
                <logger level="INFO" doc:name="Logger" message="&lt;----- Trace ID : '#[message.inboundProperties.'X-BOA-B2BI-TraceID']' ----- Authentication Type not handled ------&gt;"/>
            </otherwise>
        </choice>
        <copy-properties propertyName="*" doc:name="Copy All Inbound Properties"/>
        <logger message=" &lt;----- Trace ID : '#[flowVars.traceId]' ----- Client API Response : #[message.outboundProperties] ----&gt;" level="INFO" doc:name="Logger"/>
        <message-properties-transformer doc:name="Message Properties">
            <add-message-property key="X-BOA-B2BI-TraceID" value="#[flowVars.traceId]"/>
            <delete-message-property key="NODE_NAME"/>
            <delete-message-property key="DIRECTION"/>
            <delete-message-property key="X-BOA-B2BI-ClientID"/>
            <delete-message-property key="X-BOA-B2BI-Token"/>
        </message-properties-transformer>        
        <exception-strategy ref="RoutingExceptionStrategy" doc:name="Reference Exception Strategy"/>
    </flow>
    
    <flow name="monitoringFlow">
        <http:listener config-ref="HTTPS_Listener_Configuration" path="![p['monitoring.path']]" doc:name="HTTP" allowedMethods="GET,POST" parseRequest="false"/>
        <http:request config-ref="HTTPS_Request_Configuration_Monitor" path="${monitoring.api.path}" method="GET" doc:name="HTTP">
            <http:success-status-code-validator values="0..599"/>
        </http:request>
    </flow>
        
    <flow name="UpdateTransactionInfo">
        <set-variable variableName="NodeName" value="#[message.outboundProperties.'NODE_NAME']" doc:name="NodeName"/>
        <set-variable variableName="TraceId" value="#[message.outboundProperties.'X-BOA-B2BI-TraceID']" doc:name="TraceId"/>
        <set-variable variableName="ErrorDetails" value="#[message.outboundProperties.'ERROR_DETAILS']" doc:name="ErrorDetails"/>
        <set-variable variableName="Operation" value="#[message.outboundProperties.'GW_OPEARTION']" doc:name="Operation"/>
        <set-variable variableName="OperationType" value="#[message.outboundProperties.'GW_OPEARTION_TYPE']" doc:name="OperationType"/>
        <remove-property propertyName="*" doc:name="Remove All Properties"/>
        <message-properties-transformer doc:name="Message Properties">
            <add-message-property key="X-BOA-B2BI-TraceID" value="#[flowVars.TraceId]"/>
            <add-message-property key="GW_OPEARTION_TYPE" value="#[flowVars.OperationType]"/>
            <add-message-property key="GW_OPEARTION" value="#[flowVars.Operation]"/>
            <add-message-property key="NODE_NAME" value="#[flowVars.NodeName]"/>
            <add-message-property key="ERROR_DETAILS" value="#[flowVars.ErrorDetails]"/>            
        </message-properties-transformer>
        <http:request config-ref="HTTPS_Request_Configuration_GW" path="/b2bi-api-gateway/update-trans-info" method="PUT" followRedirects="false" doc:name="HTTP">
            <http:request-builder>
                <http:query-param paramName="status" value="#[flowVars.Status]"/>
                <http:header headerName="Authorization" value="${Authorization}"/>
            </http:request-builder>
        </http:request>
       <!--  <remove-property propertyName="Authorization" doc:name="Property"/> -->
        <catch-exception-strategy doc:name="Catch Exception Strategy">
            <logger message="&lt;---- Trace ID : '#[message.inboundProperties.'X-BOA-B2BI-TraceID']' ---- Transaction Info update failure ----&gt;" level="INFO" doc:name="Logger"/>
        </catch-exception-strategy>
    </flow>

    
</mule>



oauth.checker.service.host=b2bigateway.bankofamerica.com
oauth.checker.service.port=443
oauth.checker.service.basepath=
oauth.checker.service.path=/inbound/simulator

======

oauth.checker.service.host=host
oauth.checker.service.port=8081
oauth.checker.service.basepath=
oauth.checker.service.path=/api
