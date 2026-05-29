/* ============================================================
   Smart Cart Retail Network DDoS Simulation
   NS-3.40 — Ubuntu
   ============================================================ */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/error-model.h"
#include "ns3/v4ping-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SmartCartSim");

// ============================================================
// Gauss-Markov Mobility Helper
// ============================================================
void InstallGaussMarkov(Ptr<Node> node,
                        double startX, double startY,
                        double velocity, double direction,
                        uint32_t seed)
{
  Ptr<UniformRandomVariable> velRng =
      CreateObject<UniformRandomVariable>();
  Ptr<UniformRandomVariable> dirRng =
      CreateObject<UniformRandomVariable>();
  Ptr<NormalRandomVariable>  nVel   =
      CreateObject<NormalRandomVariable>();
  Ptr<NormalRandomVariable>  nDir   =
      CreateObject<NormalRandomVariable>();
  Ptr<UniformRandomVariable> pitRng =
      CreateObject<UniformRandomVariable>();
  Ptr<NormalRandomVariable>  nPit   =
      CreateObject<NormalRandomVariable>();

  velRng->SetAttribute("Min",
      DoubleValue(velocity - 0.3));
  velRng->SetAttribute("Max",
      DoubleValue(velocity + 0.3));
  dirRng->SetAttribute("Min",
      DoubleValue(direction));
  dirRng->SetAttribute("Max",
      DoubleValue(direction + 0.01));
  pitRng->SetAttribute("Min", DoubleValue(-0.05));
  pitRng->SetAttribute("Max", DoubleValue(0.05));

  nVel->SetAttribute("Mean",     DoubleValue(0.0));
  nVel->SetAttribute("Variance", DoubleValue(0.1));
  nVel->SetAttribute("Bound",    DoubleValue(0.3));
  nDir->SetAttribute("Mean",     DoubleValue(0.0));
  nDir->SetAttribute("Variance", DoubleValue(0.25));
  nDir->SetAttribute("Bound",    DoubleValue(0.6));
  nPit->SetAttribute("Mean",     DoubleValue(0.0));
  nPit->SetAttribute("Variance", DoubleValue(0.02));
  nPit->SetAttribute("Bound",    DoubleValue(0.04));

  velRng->SetStream(seed);
  dirRng->SetStream(seed + 1);
  nVel->SetStream(seed + 2);
  nDir->SetStream(seed + 3);

  Ptr<ListPositionAllocator> pos =
      CreateObject<ListPositionAllocator>();
  pos->Add(Vector(startX, startY, 0.0));

  MobilityHelper mob;
  mob.SetPositionAllocator(pos);
  mob.SetMobilityModel(
    "ns3::GaussMarkovMobilityModel",
    "Bounds",
        BoxValue(Box(0, 150, 0, 150, 0, 0)),
    "TimeStep",
        TimeValue(Seconds(0.5)),
    "Alpha",
        DoubleValue(0.85),
    "MeanVelocity",    PointerValue(velRng),
    "MeanDirection",   PointerValue(dirRng),
    "MeanPitch",       PointerValue(pitRng),
    "NormalVelocity",  PointerValue(nVel),
    "NormalDirection", PointerValue(nDir),
    "NormalPitch",     PointerValue(nPit));

  mob.Install(node);
}

// ============================================================
// InstallCartTraffic Helper
// ============================================================
void InstallCartTraffic(
    Ptr<Node>     node,
    Ipv4Address   serverIp,
    uint32_t      pktSize,
    std::string   dataRate,
    double        tcpOffMean,
    double        udpOffMean,
    double        icmpInterval,
    double        startTime,
    double        stopTime)
{
  // TCP — MQTT sensor data — port 1883
  OnOffHelper tcp(
      "ns3::TcpSocketFactory",
      InetSocketAddress(serverIp, 1883));
  tcp.SetAttribute("PacketSize",
      UintegerValue(pktSize));
  tcp.SetAttribute("DataRate",
      DataRateValue(DataRate(dataRate)));
  tcp.SetAttribute("OnTime", StringValue(
      "ns3::ExponentialRandomVariable[Mean=1.0]"));
  tcp.SetAttribute("OffTime", StringValue(
      "ns3::ExponentialRandomVariable[Mean="
      + std::to_string(tcpOffMean) + "]"));
  ApplicationContainer tcpApp = tcp.Install(node);
  tcpApp.Start(Seconds(startTime));
  tcpApp.Stop(Seconds(stopTime));

  // UDP — Gps data — port 8080
  OnOffHelper udp(
      "ns3::UdpSocketFactory",
      InetSocketAddress(serverIp, 8080));
  udp.SetAttribute("PacketSize",
      UintegerValue(pktSize));
  udp.SetAttribute("DataRate",
      DataRateValue(DataRate(dataRate)));
  udp.SetAttribute("OnTime", StringValue(
      "ns3::ExponentialRandomVariable[Mean=0.8]"));
  udp.SetAttribute("OffTime", StringValue(
      "ns3::ExponentialRandomVariable[Mean="
      + std::to_string(udpOffMean) + "]"));
  ApplicationContainer udpApp = udp.Install(node);
  udpApp.Start(Seconds(startTime + 0.05));
  udpApp.Stop(Seconds(stopTime));

  // ICMP — connectivity heartbeat
  V4PingHelper icmp(serverIp);
  icmp.SetAttribute("Interval",
      TimeValue(Seconds(icmpInterval)));
  icmp.SetAttribute("Size", UintegerValue(56));
  ApplicationContainer icmpApp = icmp.Install(node);
  icmpApp.Start(Seconds(startTime + 0.1));
  icmpApp.Stop(Seconds(stopTime));
}

// ============================================================
// MAIN
// ============================================================
int main(int argc, char *argv[])
{
  LogComponentEnable("SmartCartSim",
      LOG_LEVEL_INFO);

  double simTime = 300.0;
  RngSeedManager::SetSeed(42);
  RngSeedManager::SetRun(1);

  // ============================================================
  // Node Creation
  // ============================================================

  NodeContainer normalCarts;
  normalCarts.Create(20);

  NodeContainer attackerCarts;
  attackerCarts.Create(10);

  NodeContainer backgroundNodes;
  backgroundNodes.Create(2);

  NodeContainer routerNode;
  routerNode.Create(1);

  NodeContainer serverNode;
  serverNode.Create(1);

  NS_LOG_INFO("Nodes: 20 normal + 10 attacker + "
              "2 bg + 1 router + 1 server");

  // ============================================================
  // Mobility — Gauss-Markov 
  // ============================================================

  // 20 normal carts — spread across store
  InstallGaussMarkov(
      normalCarts.Get(0),  10,  10, 1.2, 0.000, 10);
  InstallGaussMarkov(
      normalCarts.Get(1),  25,  20, 0.8, 2.094, 20);
  InstallGaussMarkov(
      normalCarts.Get(2),  40,  10, 1.5, 4.189, 30);
  InstallGaussMarkov(
      normalCarts.Get(3),  55,  20, 1.0, 1.047, 40);
  InstallGaussMarkov(
      normalCarts.Get(4),  70,  10, 1.3, 3.665, 50);
  InstallGaussMarkov(
      normalCarts.Get(5),  85,  20, 0.9, 0.524, 60);
  InstallGaussMarkov(
      normalCarts.Get(6), 100,  10, 1.4, 2.618, 70);
  InstallGaussMarkov(
      normalCarts.Get(7), 115,  20, 1.1, 4.712, 80);
  InstallGaussMarkov(
      normalCarts.Get(8), 130,  10, 0.7, 1.571, 90);
  InstallGaussMarkov(
      normalCarts.Get(9), 145,  20, 1.6, 3.142, 100);
  InstallGaussMarkov(
      normalCarts.Get(10), 10,  60, 1.0, 0.785, 110);
  InstallGaussMarkov(
      normalCarts.Get(11), 25,  70, 1.2, 2.356, 120);
  InstallGaussMarkov(
      normalCarts.Get(12), 40,  60, 0.8, 4.712, 130);
  InstallGaussMarkov(
      normalCarts.Get(13), 55,  70, 1.3, 1.309, 140);
  InstallGaussMarkov(
      normalCarts.Get(14), 70,  60, 1.1, 3.927, 150);
  InstallGaussMarkov(
      normalCarts.Get(15), 85,  70, 0.9, 0.262, 160);
  InstallGaussMarkov(
      normalCarts.Get(16),100,  60, 1.4, 2.880, 170);
  InstallGaussMarkov(
      normalCarts.Get(17),115,  70, 1.0, 5.236, 180);
  InstallGaussMarkov(
      normalCarts.Get(18),130,  60, 0.7, 1.833, 190);
  InstallGaussMarkov(
      normalCarts.Get(19),145,  70, 1.5, 3.491, 200);

  // 10 attacker carts
  InstallGaussMarkov(
      attackerCarts.Get(0),  20, 120, 1.1, 1.571, 210);
  InstallGaussMarkov(
      attackerCarts.Get(1),  40, 130, 0.9, 3.927, 220);
  InstallGaussMarkov(
      attackerCarts.Get(2),  60, 120, 1.3, 0.785, 230);
  InstallGaussMarkov(
      attackerCarts.Get(3),  80, 130, 1.0, 5.236, 240);
  InstallGaussMarkov(
      attackerCarts.Get(4), 100, 120, 1.2, 2.094, 250);
  InstallGaussMarkov(
      attackerCarts.Get(5), 120, 130, 0.8, 4.189, 260);
  InstallGaussMarkov(
      attackerCarts.Get(6),  30, 140, 1.4, 1.047, 270);
  InstallGaussMarkov(
      attackerCarts.Get(7),  60, 140, 1.1, 3.665, 280);
  InstallGaussMarkov(
      attackerCarts.Get(8),  90, 140, 0.9, 0.524, 290);
  InstallGaussMarkov(
      attackerCarts.Get(9), 120, 140, 1.3, 2.618, 300);

  // 2 background nodes near entrance
  InstallGaussMarkov(
      backgroundNodes.Get(0),
        5, 148, 0.3, 0.000, 310);
  InstallGaussMarkov(
      backgroundNodes.Get(1),
      145, 148, 0.3, 3.142, 320);

  // Router and server fixed positions
  Ptr<ListPositionAllocator> fixedPos =
      CreateObject<ListPositionAllocator>();
  fixedPos->Add(Vector(75.0,  75.0, 1.5));
  fixedPos->Add(Vector(200.0, 75.0, 0.0));

  MobilityHelper fixedMob;
  fixedMob.SetPositionAllocator(fixedPos);
  fixedMob.SetMobilityModel(
      "ns3::ConstantPositionMobilityModel");
  fixedMob.Install(routerNode);
  fixedMob.Install(serverNode);

  NS_LOG_INFO("Mobility installed 150x150m");

  // ============================================================
  // WiFi — 802.11g — LogDistance
  // ============================================================

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay(
      "ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss(
      "ns3::LogDistancePropagationLossModel",
      "Exponent",          DoubleValue(3.0),
      "ReferenceDistance", DoubleValue(1.0),
      "ReferenceLoss",     DoubleValue(40.0));

  YansWifiPhyHelper wifiPhy;
  wifiPhy.SetChannel(wifiChannel.Create());
  wifiPhy.Set("TxPowerStart",  DoubleValue(20.0));
  wifiPhy.Set("TxPowerEnd",    DoubleValue(20.0));
  wifiPhy.Set("RxSensitivity", DoubleValue(-85.0));
  wifiPhy.SetPcapDataLinkType(
      WifiPhyHelper::DLT_IEEE802_11_RADIO);

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211g);
  wifi.SetRemoteStationManager(
      "ns3::ConstantRateWifiManager",
      "DataMode",
          StringValue("ErpOfdmRate54Mbps"),
      "ControlMode",
          StringValue("ErpOfdmRate6Mbps"));

  Ssid ssid = Ssid("SmartCart-Store");

  WifiMacHelper macAp;
  macAp.SetType("ns3::ApWifiMac",
                "Ssid", SsidValue(ssid));
  NetDeviceContainer apDevice =
      wifi.Install(wifiPhy, macAp, routerNode);

  WifiMacHelper macSta;
  macSta.SetType("ns3::StaWifiMac",
                 "Ssid", SsidValue(ssid),
                 "ActiveProbing",
                 BooleanValue(false));

  NetDeviceContainer normalDevices =
      wifi.Install(wifiPhy, macSta, normalCarts);
  NetDeviceContainer attackerDevices =
      wifi.Install(wifiPhy, macSta, attackerCarts);
  NetDeviceContainer backgroundDevices =
      wifi.Install(wifiPhy, macSta, backgroundNodes);

  NS_LOG_INFO("WiFi 802.11g installed");

  // ============================================================
  // P2P — Router to Server
  // ============================================================

  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate",
      StringValue("100Mbps"));
  p2p.SetChannelAttribute("Delay",
      StringValue("5ms"));
  NetDeviceContainer p2pDevices =
      p2p.Install(routerNode.Get(0),
                  serverNode.Get(0));

  NS_LOG_INFO("P2P 100Mbps 5ms installed");

  // ============================================================
  // Error Models — Noise Type 1
  // 2% normal — 5% lunch — 4% evening — 15% interference
  // ============================================================

  Ptr<RateErrorModel> errorNormal =
      CreateObject<RateErrorModel>();
  errorNormal->SetAttribute("ErrorRate",
      DoubleValue(0.02));
  errorNormal->SetAttribute("ErrorUnit",
      StringValue("ERROR_UNIT_PACKET"));
  p2pDevices.Get(1)->SetAttribute(
      "ReceiveErrorModel",
      PointerValue(errorNormal));

  Ptr<RateErrorModel> errorRush =
      CreateObject<RateErrorModel>();
  errorRush->SetAttribute("ErrorRate",
      DoubleValue(0.05));
  errorRush->SetAttribute("ErrorUnit",
      StringValue("ERROR_UNIT_PACKET"));

  Ptr<RateErrorModel> errorEvening =
      CreateObject<RateErrorModel>();
  errorEvening->SetAttribute("ErrorRate",
      DoubleValue(0.04));
  errorEvening->SetAttribute("ErrorUnit",
      StringValue("ERROR_UNIT_PACKET"));

  Ptr<RateErrorModel> errorInterference =
      CreateObject<RateErrorModel>();
  errorInterference->SetAttribute("ErrorRate",
      DoubleValue(0.15));
  errorInterference->SetAttribute("ErrorUnit",
      StringValue("ERROR_UNIT_PACKET"));

  NS_LOG_INFO("Error models installed");

  // ============================================================
  // Internet Stack + IP Addressing
  // WiFi: 10.1.1.0/24
  // P2P:  10.1.2.0/24
  // ============================================================

  InternetStackHelper stack;
  stack.Install(normalCarts);
  stack.Install(attackerCarts);
  stack.Install(backgroundNodes);
  stack.Install(routerNode);
  stack.Install(serverNode);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer apIface =
      ipv4.Assign(apDevice);
  Ipv4InterfaceContainer normalIfaces =
      ipv4.Assign(normalDevices);
  Ipv4InterfaceContainer attackerIfaces =
      ipv4.Assign(attackerDevices);
  Ipv4InterfaceContainer bgIfaces =
      ipv4.Assign(backgroundDevices);

  ipv4.SetBase("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer p2pIfaces =
      ipv4.Assign(p2pDevices);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();
  Ipv4Address serverIp = p2pIfaces.GetAddress(1);

  NS_LOG_INFO(" IP Summary");
  NS_LOG_INFO("Router: " << apIface.GetAddress(0));
  NS_LOG_INFO("Server: " << serverIp);
  for (uint32_t i = 0; i < normalCarts.GetN(); i++)
    NS_LOG_INFO("Normal  " << i << ": "
                << normalIfaces.GetAddress(i));
  for (uint32_t i = 0; i < attackerCarts.GetN(); i++)
    NS_LOG_INFO("Attacker" << i << ": "
                << attackerIfaces.GetAddress(i));
  NS_LOG_INFO("BG0: " << bgIfaces.GetAddress(0));
  NS_LOG_INFO("BG1: " << bgIfaces.GetAddress(1));

  // ============================================================
  // Packet Sinks on Server
  // ============================================================

  PacketSinkHelper sinkUdp(
      "ns3::UdpSocketFactory",
      InetSocketAddress(
          Ipv4Address::GetAny(), 8080));
  sinkUdp.Install(serverNode.Get(0))
         .Start(Seconds(0.0));

  PacketSinkHelper sinkTcpMqtt(
      "ns3::TcpSocketFactory",
      InetSocketAddress(
          Ipv4Address::GetAny(), 1883));
  sinkTcpMqtt.Install(serverNode.Get(0))
             .Start(Seconds(0.0));

  PacketSinkHelper sinkTcpAtk(
      "ns3::TcpSocketFactory",
      InetSocketAddress(
          Ipv4Address::GetAny(), 8081));
  sinkTcpAtk.Install(serverNode.Get(0))
            .Start(Seconds(0.0));


 PacketSinkHelper sinkTcpAck(
    "ns3::TcpSocketFactory",
    InetSocketAddress(
        Ipv4Address::GetAny(), 8082));
 ApplicationContainer sinkTcpAckApp =
    sinkTcpAck.Install(serverNode.Get(0));
 sinkTcpAckApp.Start(Seconds(0.0));
 sinkTcpAckApp.Stop(Seconds(simTime));

  PacketSinkHelper sinkBg(
      "ns3::UdpSocketFactory",
      InetSocketAddress(
          Ipv4Address::GetAny(), 9090));
  sinkBg.Install(serverNode.Get(0))
        .Start(Seconds(0.0));

  NS_LOG_INFO("Sinks: 8080 1883 8081 9090");

  // ============================================================
  // NORMAL BASELINE TRAFFIC — t=0 to t=300s
  // ============================================================

  NS_LOG_INFO(" Normal Baseline Traffic");

  // Cart 0-3 — Regular shopper
  // 82B 1635bps 
  for (uint32_t i = 0; i <= 3; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "1635bps", 2.3, 2.5, 2.5,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Regular 82B 1635bps");
  }

  // Cart 4-6 — Quick shopper
  // 82B 4000bps
  for (uint32_t i = 4; i <= 6; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "4000bps", 0.9, 1.0, 2.5,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Quick 82B 4000bps");
  }

  // Cart 7-9 — Slow browser
  // 82B 800bps 
  for (uint32_t i = 7; i <= 9; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "800bps", 4.5, 5.0, 5.0,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Slow 82B 800bps");
  }

  // Cart 10-11 — Bulk buyer
  // 120B 3000bps 
  for (uint32_t i = 10; i <= 11; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        120, "3000bps", 1.5, 2.0, 2.5,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Bulk 120B 3000bps");
  }

  // Cart 12-13 — Self checkout
  // 200B 8000bps 
  for (uint32_t i = 12; i <= 13; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        200, "8000bps", 1.0, 1.2, 2.5,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Checkout 200B 8000bps");
  }

  // Cart 14-15 — Idle cart
  // 82B 300bps
  for (uint32_t i = 14; i <= 15; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "300bps", 10.0, 10.0, 10.0,
        0.1*(i+1), simTime);
    NS_LOG_INFO("Cart " << i
                << " Idle 82B 300bps");
  }

  // Cart 16-17 — Mixed behaviour
  // Phase 1: slow t=0-100s
  // Phase 2: active t=100-200s
  // Phase 3: normal t=200-300s
  for (uint32_t i = 16; i <= 17; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "800bps", 4.0, 4.5, 5.0,
        0.1*(i+1), 100.0);
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "4000bps", 1.0, 1.2, 2.5,
        100.0, 200.0);
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "1635bps", 2.3, 2.5, 2.5,
        200.0, simTime);
    NS_LOG_INFO("Cart " << i
                << " Mixed variable");
  }

  // Cart 18-19 — New cart boot
  // Boot: 150B 5000bps t=0-30s
  // Normal: 82B 1635bps t=30-300s
  for (uint32_t i = 18; i <= 19; i++)
  {
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        150, "5000bps", 1.0, 1.2, 1.5,
        0.1*(i+1), 30.0);
    InstallCartTraffic(
        normalCarts.Get(i), serverIp,
        82, "1635bps", 2.3, 2.5, 2.5,
        30.0, simTime);
    NS_LOG_INFO("Cart " << i
                << " Boot 150B then normal");
  }

  // Attacker carts normal baseline
  // Hijacked but physically still shopping
  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    InstallCartTraffic(
        attackerCarts.Get(i), serverIp,
        82, "1635bps", 2.3, 2.5, 2.5,
        0.1*(i+21), simTime);
    NS_LOG_INFO("Attacker " << i
                << " normal baseline");
  }

  // Background nodes — Noise Type 2
  // 200B 50Kbps 
  for (uint32_t i = 0;
       i < backgroundNodes.GetN(); i++)
  {
    OnOffHelper bg(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 9090));
    bg.SetAttribute("PacketSize",
        UintegerValue(200));
    bg.SetAttribute("DataRate",
        DataRateValue(DataRate("50Kbps")));
    bg.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=2.0]"));
    bg.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=1.5]"));
    bg.Install(backgroundNodes.Get(i))
      .Start(Seconds(0.5*(i+1)));
    NS_LOG_INFO("BG node " << i
                << " 200B 50Kbps");
  }

  NS_LOG_INFO("All baseline traffic installed");

  // ============================================================
  // Store Opening  t=0-20s — label=0
  // ============================================================

  NS_LOG_INFO("=== Store Opening (t=0-20s) ===");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    OnOffHelper op(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 1883));
    op.SetAttribute("PacketSize",
        UintegerValue(82));
    op.SetAttribute("DataRate",
        DataRateValue(DataRate("500bps")));
    op.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.3]"));
    op.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=5.0]"));
    op.Install(normalCarts.Get(i))
      .Start(Seconds(0.5*i));
    NS_LOG_INFO("Opening cart " << i);
  }

  // ============================================================
  // Lunch Rush — t=80-110s — label=0
  // 10Kbps 3x faster — 5% packet loss
  // ============================================================

  NS_LOG_INFO("Lunch Rush (t=80-110s)");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    OnOffHelper rTcp(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 1883));
    rTcp.SetAttribute("PacketSize",
        UintegerValue(82));
    rTcp.SetAttribute("DataRate",
        DataRateValue(DataRate("10Kbps")));
    rTcp.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=1.0]"));
    rTcp.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.8]"));
    rTcp.Install(normalCarts.Get(i))
        .Start(Seconds(80.0));

    OnOffHelper rUdp(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    rUdp.SetAttribute("PacketSize",
        UintegerValue(82));
    rUdp.SetAttribute("DataRate",
        DataRateValue(DataRate("10Kbps")));
    rUdp.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.8]"));
    rUdp.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.6]"));
    rUdp.Install(normalCarts.Get(i))
        .Start(Seconds(80.0));
  }

  Simulator::Schedule(Seconds(80.0), [&]() {
    p2pDevices.Get(1)->SetAttribute(
        "ReceiveErrorModel",
        PointerValue(errorRush));
    NS_LOG_INFO("Lunch rush 5% loss");
  });
  Simulator::Schedule(Seconds(110.0), [&]() {
    p2pDevices.Get(1)->SetAttribute(
        "ReceiveErrorModel",
        PointerValue(errorNormal));
    NS_LOG_INFO("Lunch rush ended 2% loss");
  });

  // ============================================================
  // Post Lunch Quiet — t=110-140s — label=0
  // ============================================================

  NS_LOG_INFO(" Post Lunch Quiet (t=110-140s)");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    OnOffHelper ql(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 1883));
    ql.SetAttribute("PacketSize",
        UintegerValue(82));
    ql.SetAttribute("DataRate",
        DataRateValue(DataRate("2Kbps")));
    ql.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.8]"));
    ql.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=1.8]"));
    ql.Install(normalCarts.Get(i))
      .Start(Seconds(110.0));
  }
  NS_LOG_INFO("Post lunch quiet installed");

  // ============================================================
  // Firmware Update — t=140-180s — label=0
  // Carts 1,5,7 staggered
  // ============================================================

  NS_LOG_INFO(" Firmware Carts 1,5,7");

  // Cart 1 — t=140s
  OnOffHelper fw1("ns3::TcpSocketFactory",
      InetSocketAddress(serverIp, 1883));
  fw1.SetAttribute("PacketSize",
      UintegerValue(1024));
  fw1.SetAttribute("DataRate",
      DataRateValue(DataRate("512Kbps")));
  fw1.SetAttribute("OnTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=2.0]"));
  fw1.SetAttribute("OffTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=0.5]"));
  fw1.Install(normalCarts.Get(1))
     .Start(Seconds(140.0));
  NS_LOG_INFO("Firmware Cart 1 t=140s");

  // Cart 5 — t=145s
  OnOffHelper fw5("ns3::TcpSocketFactory",
      InetSocketAddress(serverIp, 1883));
  fw5.SetAttribute("PacketSize",
      UintegerValue(1024));
  fw5.SetAttribute("DataRate",
      DataRateValue(DataRate("512Kbps")));
  fw5.SetAttribute("OnTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=2.0]"));
  fw5.SetAttribute("OffTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=0.5]"));
  fw5.Install(normalCarts.Get(5))
     .Start(Seconds(145.0));
  NS_LOG_INFO("Firmware Cart 5 t=145s");

  // Cart 7 — t=150s
  OnOffHelper fw7("ns3::TcpSocketFactory",
      InetSocketAddress(serverIp, 1883));
  fw7.SetAttribute("PacketSize",
      UintegerValue(1024));
  fw7.SetAttribute("DataRate",
      DataRateValue(DataRate("512Kbps")));
  fw7.SetAttribute("OnTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=2.0]"));
  fw7.SetAttribute("OffTime", StringValue(
      "ns3::ExponentialRandomVariable"
      "[Mean=0.5]"));
  fw7.Install(normalCarts.Get(7))
     .Start(Seconds(150.0));
  NS_LOG_INFO("Firmware Cart 7 t=150s");

  // ============================================================
  // Evening Rush — t=200-230s — label=0
  // 8Kbps 2.5x faster — 4% packet loss
  // ============================================================

  NS_LOG_INFO(" Evening Rush (t=200-230s)");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    OnOffHelper eTcp(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 1883));
    eTcp.SetAttribute("PacketSize",
        UintegerValue(82));
    eTcp.SetAttribute("DataRate",
        DataRateValue(DataRate("8Kbps")));
    eTcp.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=1.2]"));
    eTcp.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.9]"));
    eTcp.Install(normalCarts.Get(i))
        .Start(Seconds(200.0));

    OnOffHelper eUdp(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    eUdp.SetAttribute("PacketSize",
        UintegerValue(82));
    eUdp.SetAttribute("DataRate",
        DataRateValue(DataRate("8Kbps")));
    eUdp.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.9]"));
    eUdp.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.7]"));
    eUdp.Install(normalCarts.Get(i))
        .Start(Seconds(200.0));
  }

  Simulator::Schedule(Seconds(200.0), [&]() {
    p2pDevices.Get(1)->SetAttribute(
        "ReceiveErrorModel",
        PointerValue(errorEvening));
    NS_LOG_INFO("Evening rush 4% loss");
  });
  Simulator::Schedule(Seconds(230.0), [&]() {
    p2pDevices.Get(1)->SetAttribute(
        "ReceiveErrorModel",
        PointerValue(errorNormal));
    NS_LOG_INFO("Evening rush ended 2% loss");
  });

  // ============================================================
  // Store Closing — t=230-260s — label=0
  // 1Kbps gradually reducing
  // ============================================================

  NS_LOG_INFO("Store Closing (t=230-260s)");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    OnOffHelper cl(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 1883));
    cl.SetAttribute("PacketSize",
        UintegerValue(82));
    cl.SetAttribute("DataRate",
        DataRateValue(DataRate("1Kbps")));
    cl.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.6]"));
    cl.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=3.0]"));
    cl.Install(normalCarts.Get(i))
      .Start(Seconds(230.0));
  }
  NS_LOG_INFO("Store closing installed");

  // ============================================================
  // Late Night — t=260-300s — label=0
  // ICMP heartbeat only — store closed
  // ============================================================

  NS_LOG_INFO("Late Night ICMP (t=260-300s)");

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    V4PingHelper lp(serverIp);
    lp.SetAttribute("Interval",
        TimeValue(Seconds(5.0)));
    lp.SetAttribute("Size", UintegerValue(56));
    lp.Install(normalCarts.Get(i))
      .Start(Seconds(260.0));
  }
  NS_LOG_INFO("Late night ICMP installed");

  // ============================================================
  // Additional Realistic Events
  // ============================================================
  // Payment burst — carts 12-13 every 60s
  // 500B 50Kbps 5s burst — payment processing
  NS_LOG_INFO("Payment Bursts Carts 12-13");
  for (double t = 60.0; t < 300.0; t += 60.0)
  {
    for (uint32_t i = 12; i <= 13; i++)
    {
      OnOffHelper pb(
          "ns3::TcpSocketFactory",
          InetSocketAddress(serverIp, 1883));
      pb.SetAttribute("PacketSize",
          UintegerValue(500));
      pb.SetAttribute("DataRate",
          DataRateValue(DataRate("50Kbps")));
      pb.SetAttribute("OnTime", StringValue(
          "ns3::ConstantRandomVariable"
          "[Constant=5.0]"));
      pb.SetAttribute("OffTime", StringValue(
          "ns3::ConstantRandomVariable"
          "[Constant=0.0]"));
      ApplicationContainer pbApp =
          pb.Install(normalCarts.Get(i));
      pbApp.Start(Seconds(t));
      pbApp.Stop(Seconds(t + 5.0));
    }
  }
  NS_LOG_INFO("Payment bursts installed");

  // Battery saving — carts 6,12,17 t=50-70s
  // 50% rate reduction — low battery
  NS_LOG_INFO("=== Battery Saving Carts 6,12,17 ===");
  std::vector<uint32_t> batteryCarts = {6,12,17};
  for (uint32_t ci : batteryCarts)
  {
    OnOffHelper bs(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    bs.SetAttribute("PacketSize",
        UintegerValue(82));
    bs.SetAttribute("DataRate",
        DataRateValue(DataRate("800bps")));
    bs.SetAttribute("OnTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=0.5]"));
    bs.SetAttribute("OffTime", StringValue(
        "ns3::ExponentialRandomVariable"
        "[Mean=4.5]"));
    ApplicationContainer bsApp =
        bs.Install(normalCarts.Get(ci));
    bsApp.Start(Seconds(50.0));
    bsApp.Stop(Seconds(70.0));
    NS_LOG_INFO("Battery saving cart " << ci);
  }

  // Multi shopper — carts 0,4,10
  // Double scanning rate for 10s
  // t=90-100s and t=210-220s
  NS_LOG_INFO("=== Multi Shopper Carts 0,4,10 ===");
  std::vector<uint32_t> multiCarts = {0,4,10};
  std::vector<double> multiTimes = {90.0, 210.0};
  for (double mt : multiTimes)
  {
    for (uint32_t ci : multiCarts)
    {
      OnOffHelper ms(
          "ns3::TcpSocketFactory",
          InetSocketAddress(serverIp, 1883));
      ms.SetAttribute("PacketSize",
          UintegerValue(82));
      ms.SetAttribute("DataRate",
          DataRateValue(DataRate("8000bps")));
      ms.SetAttribute("OnTime", StringValue(
          "ns3::ExponentialRandomVariable"
          "[Mean=1.5]"));
      ms.SetAttribute("OffTime", StringValue(
          "ns3::ExponentialRandomVariable"
          "[Mean=0.5]"));
      ApplicationContainer msApp =
          ms.Install(normalCarts.Get(ci));
      msApp.Start(Seconds(mt));
      msApp.Stop(Seconds(mt + 10.0));
      NS_LOG_INFO("Multi shopper cart " << ci
                  << " t=" << mt);
    }
  }

  // WiFi interference bursts
  // t=50s t=155s t=245s — 15% loss 3s each
  NS_LOG_INFO("=== WiFi Interference Bursts ===");
  std::vector<double> intTimes = {50.0,155.0,245.0};
  for (double it : intTimes)
  {
    Simulator::Schedule(Seconds(it), [&]() {
      p2pDevices.Get(1)->SetAttribute(
          "ReceiveErrorModel",
          PointerValue(errorInterference));
      NS_LOG_INFO("WiFi interference 15% loss");
    });
    Simulator::Schedule(Seconds(it+3.0), [&]() {
      p2pDevices.Get(1)->SetAttribute(
          "ReceiveErrorModel",
          PointerValue(errorNormal));
      NS_LOG_INFO("WiFi interference ended");
    });
  }

  NS_LOG_INFO("All normal events installed");

  // ============================================================
  // ATTACK PHASE 1 — t=80-120s — label=1
  // ALL 10 carts — UDP Small Flood
  // 60B — gradual ramp-up to 600Kbps
  // ============================================================

  NS_LOG_INFO("Attack Ph1 (t=80-120s) UDP small");

  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    bool isBurst = (i == 8 || i == 9);
    std::string onTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=3.0]" :
        "ns3::ConstantRandomVariable[Constant=40.0]";
    std::string offTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=1.0]" :
        "ns3::ConstantRandomVariable[Constant=0.0]";

    // Ramp step 1 — 10% — 60Kbps
    OnOffHelper p1r1(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p1r1.SetAttribute("PacketSize",
        UintegerValue(60));
    p1r1.SetAttribute("DataRate",
        DataRateValue(DataRate("60000bps")));
    p1r1.SetAttribute("OnTime",
        StringValue(onTime));
    p1r1.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p1r1App =
        p1r1.Install(attackerCarts.Get(i));
    p1r1App.Start(Seconds(80.0));
    p1r1App.Stop(Seconds(85.0));

    // Ramp step 2 — 30% — 180Kbps
    OnOffHelper p1r2(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p1r2.SetAttribute("PacketSize",
        UintegerValue(60));
    p1r2.SetAttribute("DataRate",
        DataRateValue(DataRate("180000bps")));
    p1r2.SetAttribute("OnTime",
        StringValue(onTime));
    p1r2.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p1r2App =
        p1r2.Install(attackerCarts.Get(i));
    p1r2App.Start(Seconds(85.0));
    p1r2App.Stop(Seconds(90.0));

    // Ramp step 3 — 60% — 360Kbps
    OnOffHelper p1r3(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p1r3.SetAttribute("PacketSize",
        UintegerValue(60));
    p1r3.SetAttribute("DataRate",
        DataRateValue(DataRate("360000bps")));
    p1r3.SetAttribute("OnTime",
        StringValue(onTime));
    p1r3.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p1r3App =
        p1r3.Install(attackerCarts.Get(i));
    p1r3App.Start(Seconds(90.0));
    p1r3App.Stop(Seconds(95.0));

    // Ramp step 4 — 100% — 600Kbps full rate
    OnOffHelper p1r4(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p1r4.SetAttribute("PacketSize",
        UintegerValue(60));
    p1r4.SetAttribute("DataRate",
        DataRateValue(DataRate("600000bps")));
    p1r4.SetAttribute("OnTime",
        StringValue(onTime));
    p1r4.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p1r4App =
        p1r4.Install(attackerCarts.Get(i));
    p1r4App.Start(Seconds(95.0));
    p1r4App.Stop(Seconds(120.0));

    NS_LOG_INFO("Ph1 Cart " << i+20
                << (isBurst ? " BURST" : "")
                << " UDP small ramp 60B");
  }

  // ============================================================
  // ATTACK PHASE 2 — t=140-180s — label=1
  // ALL 10 carts — UDP Large Flood
  // ============================================================

  NS_LOG_INFO(" Attack Ph2 (t=140-180s) UDP large");

  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    bool isBurst = (i == 8 || i == 9);
    std::string onTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=3.0]" :
        "ns3::ConstantRandomVariable[Constant=40.0]";
    std::string offTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=1.0]" :
        "ns3::ConstantRandomVariable[Constant=0.0]";

    // Ramp 10% — 150Kbps
    OnOffHelper p2r1(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p2r1.SetAttribute("PacketSize",
        UintegerValue(1400));
    p2r1.SetAttribute("DataRate",
        DataRateValue(DataRate("150000bps")));
    p2r1.SetAttribute("OnTime",
        StringValue(onTime));
    p2r1.SetAttribute("OffTime",
        StringValue(offTime));
    p2r1.Install(attackerCarts.Get(i))
        .Start(Seconds(140.0));

    // Ramp 30% — 450Kbps
    OnOffHelper p2r2(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p2r2.SetAttribute("PacketSize",
        UintegerValue(1400));
    p2r2.SetAttribute("DataRate",
        DataRateValue(DataRate("450000bps")));
    p2r2.SetAttribute("OnTime",
        StringValue(onTime));
    p2r2.SetAttribute("OffTime",
        StringValue(offTime));
    p2r2.Install(attackerCarts.Get(i))
        .Start(Seconds(145.0));

    // Ramp 60% — 900Kbps
    OnOffHelper p2r3(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p2r3.SetAttribute("PacketSize",
        UintegerValue(1400));
    p2r3.SetAttribute("DataRate",
        DataRateValue(DataRate("900000bps")));
    p2r3.SetAttribute("OnTime",
        StringValue(onTime));
    p2r3.SetAttribute("OffTime",
        StringValue(offTime));
    p2r3.Install(attackerCarts.Get(i))
        .Start(Seconds(150.0));

    // Ramp 100% — 1.5Mbps full rate
    OnOffHelper p2r4(
        "ns3::UdpSocketFactory",
        InetSocketAddress(serverIp, 8080));
    p2r4.SetAttribute("PacketSize",
        UintegerValue(1400));
    p2r4.SetAttribute("DataRate",
        DataRateValue(DataRate("1500000bps")));
    p2r4.SetAttribute("OnTime",
        StringValue(onTime));
    p2r4.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p2r4App =
        p2r4.Install(attackerCarts.Get(i));
    p2r4App.Start(Seconds(155.0));
    p2r4App.Stop(Seconds(180.0));

    NS_LOG_INFO("Ph2 Cart " << i+20
                << " UDP large ramp 1400B");
  }

  // ============================================================
  // ATTACK PHASE 3 — t=195-235s — label=1
  // ALL 10 carts — TRUE ICMP Flood
  // ============================================================

  NS_LOG_INFO("Attack Ph3 (t=195-235s) ICMP");

  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    // Ramp 10% — 10ms interval — 100pps
    V4PingHelper p3r1(serverIp);
    p3r1.SetAttribute("Interval",
        TimeValue(MilliSeconds(10)));
    p3r1.SetAttribute("Size",
        UintegerValue(56));
    ApplicationContainer p3r1App =
        p3r1.Install(attackerCarts.Get(i));
    p3r1App.Start(Seconds(195.0));
    p3r1App.Stop(Seconds(200.0));

    // Ramp 20% — 5ms interval — 200pps
    V4PingHelper p3r2(serverIp);
    p3r2.SetAttribute("Interval",
        TimeValue(MilliSeconds(5)));
    p3r2.SetAttribute("Size",
        UintegerValue(56));
    ApplicationContainer p3r2App =
        p3r2.Install(attackerCarts.Get(i));
    p3r2App.Start(Seconds(200.0));
    p3r2App.Stop(Seconds(205.0));

    // Ramp 50% — 2ms interval — 500pps
    V4PingHelper p3r3(serverIp);
    p3r3.SetAttribute("Interval",
        TimeValue(MilliSeconds(2)));
    p3r3.SetAttribute("Size",
        UintegerValue(56));
    ApplicationContainer p3r3App =
        p3r3.Install(attackerCarts.Get(i));
    p3r3App.Start(Seconds(205.0));
    p3r3App.Stop(Seconds(210.0));

    // Ramp 100% — 1ms interval — 1000pps
    V4PingHelper p3r4(serverIp);
    p3r4.SetAttribute("Interval",
        TimeValue(MilliSeconds(1)));
    p3r4.SetAttribute("Size",
        UintegerValue(56));
    ApplicationContainer p3r4App =
        p3r4.Install(attackerCarts.Get(i));
    p3r4App.Start(Seconds(210.0));
    p3r4App.Stop(Seconds(235.0));

    NS_LOG_INFO("Ph3 Cart " << i+20
                << " ICMP ramp 10ms to 1ms");
  }

  // ============================================================
  // ATTACK PHASE 4 — t=225-265s — label=1
  // ALL 10 carts — TCP SYN Flood
  // ============================================================

  NS_LOG_INFO("Attack Ph4 (t=225-265s) TCP SYN");

  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    bool isBurst = (i == 8 || i == 9);
    std::string onTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=3.0]" :
        "ns3::ConstantRandomVariable[Constant=40.0]";
    std::string offTime = isBurst ?
        "ns3::ConstantRandomVariable[Constant=1.0]" :
        "ns3::ConstantRandomVariable[Constant=0.0]";

    // Ramp 10% — 40Kbps
    OnOffHelper p4r1(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8081));
    p4r1.SetAttribute("PacketSize",
        UintegerValue(40));
    p4r1.SetAttribute("DataRate",
        DataRateValue(DataRate("40000bps")));
    p4r1.SetAttribute("OnTime",
        StringValue(onTime));
    p4r1.SetAttribute("OffTime",
        StringValue(offTime));
    p4r1.Install(attackerCarts.Get(i))
        .Start(Seconds(225.0));

    // Ramp 30% — 120Kbps
    OnOffHelper p4r2(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8081));
    p4r2.SetAttribute("PacketSize",
        UintegerValue(40));
    p4r2.SetAttribute("DataRate",
        DataRateValue(DataRate("120000bps")));
    p4r2.SetAttribute("OnTime",
        StringValue(onTime));
    p4r2.SetAttribute("OffTime",
        StringValue(offTime));
    p4r2.Install(attackerCarts.Get(i))
        .Start(Seconds(230.0));

    // Ramp 60% — 240Kbps
    OnOffHelper p4r3(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8081));
    p4r3.SetAttribute("PacketSize",
        UintegerValue(40));
    p4r3.SetAttribute("DataRate",
        DataRateValue(DataRate("240000bps")));
    p4r3.SetAttribute("OnTime",
        StringValue(onTime));
    p4r3.SetAttribute("OffTime",
        StringValue(offTime));
    p4r3.Install(attackerCarts.Get(i))
        .Start(Seconds(235.0));

    // Ramp 100% — 400Kbps full rate
    OnOffHelper p4r4(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8081));
    p4r4.SetAttribute("PacketSize",
        UintegerValue(40));
    p4r4.SetAttribute("DataRate",
        DataRateValue(DataRate("400000bps")));
    p4r4.SetAttribute("OnTime",
        StringValue(onTime));
    p4r4.SetAttribute("OffTime",
        StringValue(offTime));
    ApplicationContainer p4r4App =
        p4r4.Install(attackerCarts.Get(i));
    p4r4App.Start(Seconds(240.0));
    p4r4App.Stop(Seconds(265.0));

    NS_LOG_INFO("Ph4 Cart " << i+20
                << " TCP SYN ramp 40B");
  }

  // ============================================================
  // ATTACK PHASE 5 — t=260-290s — label=1
  // ALL 10 carts — TCP ACK Flood
  // ============================================================


NS_LOG_INFO(" Attack Ph5 (t=260-290s) ACK flood");

for (uint32_t i = 0;
     i < attackerCarts.GetN(); i++)
{
    // Ramp 10% — small max bytes
    BulkSendHelper p5r1(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8082));
    p5r1.SetAttribute("MaxBytes",
        UintegerValue(5000));
    p5r1.SetAttribute("SendSize",
        UintegerValue(40));
    ApplicationContainer p5r1App =
        p5r1.Install(
            attackerCarts.Get(i));
    p5r1App.Start(Seconds(260.0));
    p5r1App.Stop(Seconds(265.0));

    // Ramp 30%
    BulkSendHelper p5r2(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8082));
    p5r2.SetAttribute("MaxBytes",
        UintegerValue(15000));
    p5r2.SetAttribute("SendSize",
        UintegerValue(40));
    ApplicationContainer p5r2App =
        p5r2.Install(
            attackerCarts.Get(i));
    p5r2App.Start(Seconds(265.0));
    p5r2App.Stop(Seconds(270.0));

    // Ramp 60%
    BulkSendHelper p5r3(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8082));
    p5r3.SetAttribute("MaxBytes",
        UintegerValue(30000));
    p5r3.SetAttribute("SendSize",
        UintegerValue(40));
    ApplicationContainer p5r3App =
        p5r3.Install(
            attackerCarts.Get(i));
    p5r3App.Start(Seconds(270.0));
    p5r3App.Stop(Seconds(275.0));

    // Ramp 100% — unlimited bytes
    BulkSendHelper p5r4(
        "ns3::TcpSocketFactory",
        InetSocketAddress(serverIp, 8082));
    p5r4.SetAttribute("MaxBytes",
        UintegerValue(0));
    p5r4.SetAttribute("SendSize",
        UintegerValue(40));
    ApplicationContainer p5r4App =
        p5r4.Install(
            attackerCarts.Get(i));
    p5r4App.Start(Seconds(275.0));
    p5r4App.Stop(Seconds(290.0));

    NS_LOG_INFO("Ph5 Cart " << i+20
        << " ACK flood BulkSend");
}
  // ============================================================
  // PCAP Capture
  // AP pcap primary for feature extraction
  // ============================================================

  wifiPhy.EnablePcap(
      "smartcart-normal",    normalDevices);
  wifiPhy.EnablePcap(
      "smartcart-attacker",  attackerDevices);
  wifiPhy.EnablePcap(
      "smartcart-bg",        backgroundDevices);
  wifiPhy.EnablePcap(
      "smartcart-ap",        apDevice);
  p2p.EnablePcap(
      "smartcart-server",    p2pDevices);

  NS_LOG_INFO("PCAP capture enabled");

  // ============================================================
  // NetAnim
  // ============================================================

  AnimationInterface anim("smartcart-sim.xml");
  anim.SetMaxPktsPerTraceFile(2000000);
  anim.SetMobilityPollInterval(Seconds(0.5));

  for (uint32_t i = 0;
       i < normalCarts.GetN(); i++)
  {
    anim.UpdateNodeColor(
        normalCarts.Get(i), 0, 200, 0);
    anim.UpdateNodeSize(
        normalCarts.Get(i)->GetId(), 2.5, 2.5);
    anim.UpdateNodeDescription(
        normalCarts.Get(i),
        "N" + std::to_string(i));
  }
  for (uint32_t i = 0;
       i < attackerCarts.GetN(); i++)
  {
    anim.UpdateNodeColor(
        attackerCarts.Get(i), 255, 0, 0);
    anim.UpdateNodeSize(
        attackerCarts.Get(i)->GetId(), 2.5, 2.5);
    anim.UpdateNodeDescription(
        attackerCarts.Get(i),
        "A" + std::to_string(i+20));
  }
  for (uint32_t i = 0;
       i < backgroundNodes.GetN(); i++)
  {
    anim.UpdateNodeColor(
        backgroundNodes.Get(i), 255, 255, 0);
    anim.UpdateNodeSize(
        backgroundNodes.Get(i)->GetId(), 2.0, 2.0);
    anim.UpdateNodeDescription(
        backgroundNodes.Get(i),
        "BG" + std::to_string(i));
  }
  anim.UpdateNodeColor(
      routerNode.Get(0), 255, 165, 0);
  anim.UpdateNodeSize(
      routerNode.Get(0)->GetId(), 5.0, 5.0);
  anim.UpdateNodeDescription(
      routerNode.Get(0), "Router");
  anim.UpdateNodeColor(
      serverNode.Get(0), 0, 0, 255);
  anim.UpdateNodeSize(
      serverNode.Get(0)->GetId(), 5.0, 5.0);
  anim.UpdateNodeDescription(
      serverNode.Get(0), "Server");

  NS_LOG_INFO("NetAnim configured");

  // ============================================================
  // Run Simulation
  // ============================================================

  NS_LOG_INFO("=== Starting 300s Simulation ===");

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();
  Simulator::Destroy();


  return 0;

} // end of main()
