Kerberos Simulator
==================

The Kerberos Simulator can fully simulate a Kerberos authentication.

It uses protobufs on top of a UDP-Socket to communicate from client to kdc.

Supports cross-realm authentication.


This application consists out of three Components:
- Client
- Service
- Key-Distribution-Center (KDC)


It uses shared dependencies, these dependencies are contained in the *shared* directory.

### Run and Build Application

To run/build the application, you will need Bazel and Go installed.

##### Key-Distribution-Center

The KDC consumes a local *database.yaml* configuration file, that acts as database for the simulator.

It looks for a "database.yaml" file in following directories (relative to the executable): ".", "./database", "./key-distribution-center".

In the *key-distribution-center* directory, you will find an example database file, this file is also automatically used if you use bazel run.

The KDC runs on port 5232 by default.

To run the KDC you can use following command:
```bash
bazel run //key-distribution-center
```

To build the KDC binary you can use following command:
```bash
bazel build //key-distribution-center
```

##### Service

The example service, consumes a local *database.yaml* configuration file, that acts as database.

It looks for a "database.yaml" file in following directories (relative to the executable): ".", "./database", "./service".

In the *service* directory, you will find an example database file, this file is also automatically used if you use bazel run.

The service runs on port 5233 by default.

To run the service you can use following command:
```bash
bazel run //service
```

To build the service binary you can use following command:
```bash
bazel build //service
```

##### Client

The client example, very simplified does something like this:

- Request Serviceprincipal from Service
- Request TGT from KDC
- Decrypts CT and stores the SK_TGS
- Requests ST from KDC
- Decrypts CT and stores the SK_SVC
- Connects to the Service

As you can see it asks the service for its principalname instead of using a dns server.
Credentials/Tickets are stored directly in the clients memory, credentials are not written to the disk.

To run the client (to default kdc/svc port) you can use following command:
```bash
bazel run //client -- :5233 :5232
```

To build the service binary you can use following command:
```bash
bazel build //client
```

### Limitations

This simulator was designed purely for demonstration. While it follows the basic steps of the official MIT-Kerberos, it was created without any reference to how MIT/Heimdahl-Kerberos manages the Kerberos protocol. As a result, its approach to information transmission, encryption, and other processes is distinct.

The KDC uses a *yaml* configuration as database, this obviously doesn't scale on a productive software.

The client and service are designed simply and currently lack features such as credential caching and an enhanced user experience.