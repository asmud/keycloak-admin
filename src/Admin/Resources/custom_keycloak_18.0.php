<?php

require 'Definitions/keycloak-1_0.php';
return array(
    'name'        => 'Keycloak',
    'baseUri' => $config['baseUri'],
    'apiVersion'  => '1.1',
    'operations'  => array(
        // Attack Detection
        'getBruteForceUserStatus' => array(
            'uri' => 'admin/realms/{realm}/attack-detection/brute-force/users/{userId}',
            'description' => 'Get status of a username in brute force detection',
            'httpMethod' => 'GET',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'userId' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                )
            )
        ),
        'generateClientCertificate' => array(
            'uri' => 'admin/realms/{realm}/clients/{id}/certificates/{attr}/generate',
            'description' => 'Generate a new certificate with new key pair',
            'httpMethod' => 'POST',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'attr' => array(
                    'location'    => 'uri',
                    'description' => 'attribute prefix', // one acceptable value is jwt.credential
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Client Role Mappings
        'getGroupClientRoleMappings' => array(
            'uri' => 'admin/realms/{realm}/groups/{id}/role-mappings/clients/{client}',
            'description' => 'Get client-level role mappings for the group, and the app',
            'httpMethod' => 'GET',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client' => array(
                    'location'    => 'uri',
                    'description' => 'Client id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getUserClientRoleMappings' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/role-mappings/clients/{client}',
            'description' => 'Get client-level role mappings for the user, and the app',
            'httpMethod' => 'GET',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client' => array(
                    'location'    => 'uri',
                    'description' => 'Client id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Clients
        'getClients' => array(
            'uri'         => 'admin/realms/{realm}/clients',
            'description' => 'Get clients belonging to the realm Returns a list of clients belonging to the realm',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'clientId' => array(
                    'location'    => 'query',
                    'description' => 'filter by clientId',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'viewableOnly' => array(
                    'location'    => 'query',
                    'description' => 'filter clients that cannot be viewed in full by admin',
                    'type'        => 'boolean',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'getClient' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}',
            'description' => 'Get representation of the client',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'generateClientSecret' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/client-secret',
            'description' => 'Generate a new secret for the client',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getClientSecret' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/client-secret',
            'description' => 'Get the client secret',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getClientExampleAccessToken' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/evaluate-scopes/generate-example-access-token',
            'description' => 'Create JSON with payload of example access token',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'scope' => array(
                    'location'    => 'query',
                    'description' => 'Scope',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'userId' => array(
                    'location'    => 'query',
                    'description' => 'User Id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getClientOfflineSessionsCount' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/offline-session-count',
            'description' => 'Get application offline session count Returns a number of offline user sessions associated with this client { "count": number }',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getClientOfflineSessions' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/offline-sessions',
            'description' => 'Get offline sessions for client Returns a list of offline user sessions associated with this client',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'first' => array(
                    'location'    => 'query',
                    'description' => 'Paging offset',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'max' => array(
                    'location'    => 'query',
                    'description' => 'Maximum results size (defaults to 100)',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getClientSessions' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/user-sessions',
            'description' => 'Get user sessions for client Returns a list of user sessions associated with this client',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Groups
        'createGroup' => array(
            'uri'         => 'admin/realms/{realm}/groups',
            'description' => 'create or add a top level realm groupSet or create child.',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $GroupRepresentation
        ),
        'getGroups' => array(
            'uri'         => 'admin/realms/{realm}/groups',
            'description' => 'Get group hierarchy.',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'briefRepresentation' => array(
                    'location'    => 'query',
                    'description' => 'Wether to return only name and ids or full objects default true',
                    'type'        => 'boolean',
                    'required'    => false,
                ),
                'first' => array(
                    'location'    => 'query',
                    'description' => 'Pagination offset',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'max' => array(
                    'location'    => 'query',
                    'description' => 'Maximum results size (defaults to 100)',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'search' => array(
                    'location'    => 'query',
                    'description' => 'search string',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getGroup' => array(
            'uri'         => 'admin/realms/{realm}/groups/{id}',
            'description' => 'Get Group',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'createChildGroup' => array(
            'uri'         => 'admin/realms/{realm}/groups/{groupId}/children',
            'description' => 'Set or create child.',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'groupId' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $GroupRepresentation
        ),
        'getGroupMembers' => array(
            'uri'         => 'admin/realms/{realm}/groups/{id}/members',
            'description' => 'Get users Returns a list of users, filtered according to query parameters',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'briefRepresentation' => array(
                    'location'    => 'query',
                    'description' => 'Only return basic information (only guaranteed to return id, username, created, first and last name, email, enabled state, email verification state, federation link, and access. Note that it means that namely user attributes, required actions, and not before are not returned.)',
                    'type'        => 'boolean',
                    'required'    => false,
                ),
                'first' => array(
                    'location'    => 'query',
                    'description' => 'Pagination offset',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'max' => array(
                    'location'    => 'query',
                    'description' => 'Maximum results size (defaults to 100)',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Realm Key
        'getRealmKeys' => array(
            'uri'         => 'admin/realms/{realm}/keys',
            'description' => 'Get Realm keys',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'clearExternalPublicKeysCache' => array(
            'uri'         => 'admin/realms/{realm}/clear-keys-cache',
            'description' => 'Clear cache of external public keys (Public keys of clients or Identity providers)',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'clearRealmCache' => array(
            'uri'         => 'admin/realms/{realm}/clear-realm-cache',
            'description' => 'Clear realm cache',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'clearUserCache' => array(
            'uri'         => 'admin/realms/{realm}/clear-user-cache',
            'description' => 'Clear user cache',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getGroupByPath' => array(
            'uri'         => 'admin/realms/{realm}/group-by-path/{path}',
            'description' => 'Get user group by path',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'path' => array(
                    'location'    => 'uri',
                    'description' => 'path',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'logoutAllUsers' => array(
            'uri'         => 'admin/realms/{realm}/logout-all',
            'description' => 'Removes all user sessions.',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'testSMTPConnection' => array(
            'uri'         => 'admin/realms/{realm}/testSMTPConnection',
            'description' => 'Test SMTP connection with current logged in user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $SMTPSettingsRepresentation
        ),
        // Role Mapper
        'addGlobalRolesToUser' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/role-mappings/realm',
            'description' => 'Add realm-level role mappings to the user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User Id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'roles' => array(
                    'location' => 'fullBody',
                    'type' => 'array',
                    'items' => array(
                        'type' => 'object', 'properties' => $RoleRepresentation
                    ),
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getUserRealmRoleMappings' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/role-mappings/realm',
            'description' => 'Get realm-level role mappings',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User Id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'deleteUserRealmRoleMappings' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/role-mappings/realm',
            'description' => 'Delete realm-level role mappings',
            'httpMethod'  => 'DELETE',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User Id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'roles' => array(
                    'location' => 'fullBody',
                    'type' => 'array',
                    'items' => array(
                        'type' => 'object', 'properties' => $RoleRepresentation
                    ),
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Roles
        'createClientRole' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/roles',
            'description' => 'Create a new role for the realm or client',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'realm name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $RoleRepresentation
        ),
        'getClientRoles' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/roles',
            'description' => 'Get all roles for the realm or client (Client Specific)',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'realm name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'getClientRole' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/roles/{role-name}',
            'description' => 'Get a role by name (Client Specific)',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'realm name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'role-name' => array(
                    'location'    => 'uri',
                    'description' => 'role’s name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'updateClientRole' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/roles/{role-name}',
            'description' => 'Update a role by name',
            'httpMethod'  => 'PUT',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'realm name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'role-name' => array(
                    'location'    => 'uri',
                    'description' => 'role’s name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $RoleRepresentation
        ),
        'deleteClientRole' => array(
            'uri'         => 'admin/realms/{realm}/clients/{id}/roles/{role-name}',
            'description' => 'Delete a role for the realm or client by name',
            'httpMethod'  => 'DELETE',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'realm name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'id of client (not client-id)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'role-name' => array(
                    'location'    => 'uri',
                    'description' => 'role’s name (not id!)',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        // Users
        'createUser' => array(
            'uri' => 'admin/realms/{realm}/users',
            'description' => 'Create a new user Username must be unique.',
            'httpMethod' => 'POST',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $UserRepresentation
        ),
        'getUserCount' => array(
            'uri'         => 'admin/realms/{realm}/users/count',
            'description' => 'Get the number of users',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'emailVerified' => array(
                    'location'    => 'query',
                    'type'        => 'boolean',
                    'required'    => false,
                ),
                'email' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'firstName' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'lastName' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'search' => array(
                    'location'    => 'query',
                    'description' => 'A String contained in username, first or last name, or email',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'username' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'getUsers' => array(
            'uri'         => 'admin/realms/{realm}/users',
            'description' => 'Get users Returns a list of users, filtered according to query parameters',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'briefRepresentation' => array(
                    'location'    => 'query',
                    'type'        => 'boolean',
                    'required'    => false,
                ),
                'email' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'exact' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                    'enum'        => ['true', 'false'],
                ),
                'first' => array(
                    'location'    => 'query',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'firstName' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'lastName' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'max' => array(
                    'location'    => 'query',
                    'description' => 'Maximum results size (defaults to 100)',
                    'type'        => 'integer',
                    'required'    => false,
                ),
                'search' => array(
                    'location'    => 'query',
                    'description' => 'A String contained in username, first or last name, or email',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'username' => array(
                    'location'    => 'query',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'q' => array(
                    'location'    => 'query',
                    'description' => 'A query to search for custom attributes, in the format \'key1:value2 key2:value2\'',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'getUser' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}',
            'description' => 'Get representation of the user',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getUserGroups' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/groups',
            'description' => 'Get the user groups of a specific user',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'getUserConsents' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/consents',
            'description' => 'Get the consents granted by a user',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'updateUser' => array(
            'uri' => 'admin/realms/{realm}/users/{id}',
            'description' => 'Update a user (Username must be unique)',
            'httpMethod' => 'PUT',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $UserRepresentation
        ),
        'deleteUser' => array(
            'uri' => 'admin/realms/{realm}/users/{id}',
            'description' => 'Delete a user',
            'httpMethod' => 'DELETE',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'sendVerifyEmail' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/send-verify-email',
            'description' => 'Send an email-verification email to the user An email contains a link the user can click to verify their email address.',
            'httpMethod' => 'PUT',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client_id' => array(
                    'location'    => 'query',
                    'description' => 'Client id',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'redirect_uri' => array(
                    'location'    => 'query',
                    'description' => 'Redirect uri',
                    'type'        => 'string',
                    'required'    => false,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'getUserSessions' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/sessions',
            'description' => 'Get sessions associated with the user',
            'httpMethod' => 'GET',
            'parameters' => array(
                'realm' => array(
                    'location' => 'uri',
                    'description' => 'The Realm name',
                    'type' => 'string',
                    'required' => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                )
            )
        ),
        'getUserCredentials' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/credentials',
            'description' => 'Get credentials associated with the user',
            'httpMethod' => 'GET',
            'parameters' => array(
                'realm' => array(
                    'location' => 'uri',
                    'description' => 'The Realm name',
                    'type' => 'string',
                    'required' => true,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'addUserToGroup' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/groups/{groupId}',
            'description' => 'Assign a specific user to a specific group',
            'httpMethod' => 'PUT',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'groupId' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'deleteUserFromGroup' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/groups/{groupId}',
            'description' => 'Remove a specific user from a specific group',
            'httpMethod' => 'DELETE',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'groupId' => array(
                    'location'    => 'uri',
                    'description' => 'Group id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ),
        ),
        'resetUserPassword' => array(
            'uri' => 'admin/realms/{realm}/users/{id}/reset-password',
            'description' => 'Set up a new password for the user',
            'httpMethod' => 'PUT',
            'parameters' => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            ) + $CredentialRepresentation,
        ),
        'getSocialLogins' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/federated-identity',
            'description' => 'Get social logins associated with the user',
            'httpMethod'  => 'GET',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'removeSocialLogin' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/federated-identity/{providerId}',
            'description' => 'Remove social login associated with the user',
            'httpMethod'  => 'DELETE',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location'    => 'uri',
                    'description' => 'User id',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'providerId' => array(
                    'location'    => 'uri',
                    'description' => 'The Provider ID',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'logoutUser' => array(
            'uri'         => 'admin/realms/{realm}/users/{id}/logout',
            'description' => 'Remove all sessions associated with the user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'id' => array(
                    'location' => 'uri',
                    'description' => 'User id',
                    'type' => 'string',
                    'required' => true
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                ),
            )
        ),
        'login' => array(
            'uri'         => 'realms/{realm}/protocol/openid-connect/token',
            'description' => 'Login user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client_id' => array(
                    'location' => 'formParam',
                    'description' => 'Client ID',
                    'type' => 'string',
                    'required' => true
                ),
                'grant_type' => array(
                    'location' => 'formParam',
                    'description' => 'Password grant type',
                    'type' => 'string',
                    'default' => 'password',
                    'static' => true
                ),
                'username' => array(
                    'location' => 'formParam',
                    'description' => 'Username',
                    'type' => 'string',
                    'required' => true
                ),
                'password' => array(
                    'location' => 'formParam',
                    'description' => 'Password for user',
                    'type' => 'string',
                    'required' => true
                ),
                'client_secret' => array(
                    'location' => 'formParam',
                    'description' => 'Client Secret',
                    'type' => 'string',
                    'required' => false
                )
            )
        ),
        'clientLogin' => array(
            'uri'         => 'realms/{realm}/protocol/openid-connect/token',
            'description' => 'Login user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client_id' => array(
                    'location' => 'formParam',
                    'description' => 'Client ID',
                    'type' => 'string',
                    'required' => true
                ),
                'grant_type' => array(
                    'location' => 'formParam',
                    'description' => 'Client Credential grant type',
                    'type' => 'string',
                    'default' => 'client_credentials',
                    'static' => true
                ),
                'client_secret' => array(
                    'location' => 'formParam',
                    'description' => 'Client Secret',
                    'type' => 'string',
                    'required' => false
                )
            )
        ),
        'refreshLogin' => array(
            'uri'         => 'realms/{realm}/protocol/openid-connect/token',
            'description' => 'Login user',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'client_id' => array(
                    'location' => 'formParam',
                    'description' => 'Client ID',
                    'type' => 'string',
                    'required' => true
                ),
                'grant_type' => array(
                    'location' => 'formParam',
                    'description' => 'Refresh token grant type',
                    'type' => 'string',
                    'default' => 'refresh_token',
                    'static' => true
                ),
                'refresh_token' => array(
                    'location' => 'formParam',
                    'description' => 'Refresh Token',
                    'type' => 'string',
                    'required' => true
                ),
                'client_secret' => array(
                    'location' => 'formParam',
                    'description' => 'Client Secret',
                    'type' => 'string',
                    'required' => false
                )
            )
        ),
        'userInfo' => array(
            'uri'         => 'realms/{realm}/protocol/openid-connect/userinfo',
            'description' => 'Get user info',
            'httpMethod'  => 'POST',
            'parameters'  => array(
                'realm' => array(
                    'location'    => 'uri',
                    'description' => 'The Realm name',
                    'type'        => 'string',
                    'required'    => true,
                ),
                'Authorization' => array(
                    'location'    => 'header',
                    'description' => 'Authorization token',
                    'type'        => 'string',
                    'required'    => true,
                    'default'     => null,
                )
            )
        )
    ) //End of Operations Array
);//End of return array
