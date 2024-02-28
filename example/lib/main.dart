/// Copyright (C) 2018-2022 Jason C.H
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Lesser General Public
/// License as published by the Free Software Foundation; either
/// version 2.1 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Lesser General Public License for more details.
import 'package:flutter/material.dart';
import 'package:flutter_vpn/flutter_vpn.dart';
import 'package:flutter_vpn/state.dart';

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _addressController = TextEditingController(text: 'newh.oscardownload.xyz');
  final _usernameController = TextEditingController(text: 'abbas');
  final _passwordController = TextEditingController(text: 'abbas');
  final _portController = TextEditingController(text: '4500');

  var state = FlutterVpnState.disconnected;
  CharonErrorState? charonState = CharonErrorState.NO_ERROR;

  @override
  void initState() {
    FlutterVpn.prepare();
    FlutterVpn.onStateChanged.listen((s) => setState(() => state = s));
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Flutter VPN'),
        ),
        body: ListView(
          padding: const EdgeInsets.all(12),
          children: <Widget>[
            Text('Current State: $state'),
            Text('Current Charon State: $charonState'),
            TextFormField(
              controller: _addressController,
              decoration: const InputDecoration(icon: Icon(Icons.map_outlined)),
            ),
            TextFormField(
              controller: _usernameController,
              decoration: const InputDecoration(
                icon: Icon(Icons.person_outline),
              ),
            ),
            TextFormField(
              controller: _passwordController,
              obscureText: false,
              decoration: const InputDecoration(icon: Icon(Icons.lock_outline)),
            ),
            TextFormField(
              controller: _portController,
              obscureText: false,
              decoration: const InputDecoration(icon: Icon(Icons.network_locked_sharp)),
            ),
            ElevatedButton(
              child: const Text('Connect'),
              onPressed: () => FlutterVpn.connectSSH(
                server: _addressController.text,
                username: _usernameController.text,
                password: _passwordController.text,
                port: int.parse(_portController.text),
                udpGW: 7301,
              ),
            ),
            ElevatedButton(
              child: const Text('Disconnect_SSH'),
              onPressed: () => FlutterVpn.disconnectSsh(),
            ),
            ElevatedButton(
              child: const Text('Update State'),
              onPressed: () async {
                var newState = await FlutterVpn.currentState;
                setState(() => state = newState);
              },
            ),
            ElevatedButton(
              child: const Text('Update Charon State'),
              onPressed: () async {
                var newState = await FlutterVpn.charonErrorState;
                setState(() => charonState = newState);
              },
            ),
          ],
        ),
      ),
    );
  }
}
