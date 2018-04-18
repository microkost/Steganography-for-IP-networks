namespace SteganographyFramework
{
    partial class MainWindow
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.groupBoxServer = new System.Windows.Forms.GroupBox();
            this.textBoxServerStatus = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.buttonListen = new System.Windows.Forms.Button();
            this.numericUpDownServerPort = new System.Windows.Forms.NumericUpDown();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.comboBoxServerAddress = new System.Windows.Forms.ComboBox();
            this.textBoxDebug = new System.Windows.Forms.TextBox();
            this.groupBoxClient = new System.Windows.Forms.GroupBox();
            this.textBoxClientStatus = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.buttonClient = new System.Windows.Forms.Button();
            this.numericUpDownClientPort = new System.Windows.Forms.NumericUpDown();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.comboBoxClientAddress = new System.Windows.Forms.ComboBox();
            this.buttonPlus = new System.Windows.Forms.Button();
            this.checkBoxServer = new System.Windows.Forms.CheckBox();
            this.checkBoxClient = new System.Windows.Forms.CheckBox();
            this.groupBoxMethod = new System.Windows.Forms.GroupBox();
            this.label9 = new System.Windows.Forms.Label();
            this.listBoxMethod = new System.Windows.Forms.ListBox();
            this.textBoxSecret = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.textBoxDestination = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.backgroundWorkerDebugPrinter = new System.ComponentModel.BackgroundWorker();
            this.groupBoxServer.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).BeginInit();
            this.groupBoxClient.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).BeginInit();
            this.groupBoxMethod.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBoxServer
            // 
            this.groupBoxServer.Controls.Add(this.textBoxServerStatus);
            this.groupBoxServer.Controls.Add(this.label3);
            this.groupBoxServer.Controls.Add(this.buttonListen);
            this.groupBoxServer.Location = new System.Drawing.Point(13, 328);
            this.groupBoxServer.Name = "groupBoxServer";
            this.groupBoxServer.Size = new System.Drawing.Size(261, 70);
            this.groupBoxServer.TabIndex = 1;
            this.groupBoxServer.TabStop = false;
            this.groupBoxServer.Text = "Server";
            // 
            // textBoxServerStatus
            // 
            this.textBoxServerStatus.Location = new System.Drawing.Point(58, 41);
            this.textBoxServerStatus.Name = "textBoxServerStatus";
            this.textBoxServerStatus.ReadOnly = true;
            this.textBoxServerStatus.Size = new System.Drawing.Size(197, 20);
            this.textBoxServerStatus.TabIndex = 8;
            this.textBoxServerStatus.Text = "not connected";
            this.textBoxServerStatus.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(18, 44);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(35, 13);
            this.label3.TabIndex = 7;
            this.label3.Text = "status";
            // 
            // buttonListen
            // 
            this.buttonListen.Location = new System.Drawing.Point(58, 11);
            this.buttonListen.Name = "buttonListen";
            this.buttonListen.Size = new System.Drawing.Size(199, 23);
            this.buttonListen.TabIndex = 0;
            this.buttonListen.Text = "Listen";
            this.buttonListen.UseVisualStyleBackColor = true;
            this.buttonListen.Click += new System.EventHandler(this.ButtonListen_Click);
            // 
            // numericUpDownServerPort
            // 
            this.numericUpDownServerPort.Location = new System.Drawing.Point(54, 60);
            this.numericUpDownServerPort.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.numericUpDownServerPort.Name = "numericUpDownServerPort";
            this.numericUpDownServerPort.Size = new System.Drawing.Size(201, 20);
            this.numericUpDownServerPort.TabIndex = 5;
            this.numericUpDownServerPort.Value = new decimal(new int[] {
            11000,
            0,
            0,
            0});
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(23, 61);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(25, 13);
            this.label2.TabIndex = 4;
            this.label2.Text = "port";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(6, 37);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(42, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "runs on";
            // 
            // comboBoxServerAddress
            // 
            this.comboBoxServerAddress.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxServerAddress.FormattingEnabled = true;
            this.comboBoxServerAddress.Location = new System.Drawing.Point(54, 36);
            this.comboBoxServerAddress.Name = "comboBoxServerAddress";
            this.comboBoxServerAddress.Size = new System.Drawing.Size(201, 21);
            this.comboBoxServerAddress.TabIndex = 2;
            this.comboBoxServerAddress.SelectedIndexChanged += new System.EventHandler(this.ComboBoxServerAddress_SelectedIndexChanged);
            // 
            // textBoxDebug
            // 
            this.textBoxDebug.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.textBoxDebug.Location = new System.Drawing.Point(558, 12);
            this.textBoxDebug.Multiline = true;
            this.textBoxDebug.Name = "textBoxDebug";
            this.textBoxDebug.ReadOnly = true;
            this.textBoxDebug.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxDebug.Size = new System.Drawing.Size(504, 387);
            this.textBoxDebug.TabIndex = 2;
            // 
            // groupBoxClient
            // 
            this.groupBoxClient.Controls.Add(this.textBoxClientStatus);
            this.groupBoxClient.Controls.Add(this.label4);
            this.groupBoxClient.Controls.Add(this.buttonClient);
            this.groupBoxClient.Location = new System.Drawing.Point(287, 328);
            this.groupBoxClient.Name = "groupBoxClient";
            this.groupBoxClient.Size = new System.Drawing.Size(266, 70);
            this.groupBoxClient.TabIndex = 9;
            this.groupBoxClient.TabStop = false;
            this.groupBoxClient.Text = "Client";
            // 
            // textBoxClientStatus
            // 
            this.textBoxClientStatus.Location = new System.Drawing.Point(55, 41);
            this.textBoxClientStatus.Name = "textBoxClientStatus";
            this.textBoxClientStatus.ReadOnly = true;
            this.textBoxClientStatus.Size = new System.Drawing.Size(204, 20);
            this.textBoxClientStatus.TabIndex = 8;
            this.textBoxClientStatus.Text = "not connected";
            this.textBoxClientStatus.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(15, 44);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(35, 13);
            this.label4.TabIndex = 7;
            this.label4.Text = "status";
            // 
            // buttonClient
            // 
            this.buttonClient.Location = new System.Drawing.Point(5, 13);
            this.buttonClient.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.buttonClient.Name = "buttonClient";
            this.buttonClient.Size = new System.Drawing.Size(254, 23);
            this.buttonClient.TabIndex = 14;
            this.buttonClient.Text = "Send";
            this.buttonClient.UseVisualStyleBackColor = true;
            this.buttonClient.Click += new System.EventHandler(this.ButtonSteganogr_Click);
            // 
            // numericUpDownClientPort
            // 
            this.numericUpDownClientPort.Location = new System.Drawing.Point(58, 62);
            this.numericUpDownClientPort.Maximum = new decimal(new int[] {
            65535,
            0,
            0,
            0});
            this.numericUpDownClientPort.Name = "numericUpDownClientPort";
            this.numericUpDownClientPort.Size = new System.Drawing.Size(201, 20);
            this.numericUpDownClientPort.TabIndex = 5;
            this.numericUpDownClientPort.Value = new decimal(new int[] {
            11001,
            0,
            0,
            0});
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(28, 63);
            this.label5.Name = "label5";
            this.label5.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.label5.Size = new System.Drawing.Size(25, 13);
            this.label5.TabIndex = 4;
            this.label5.Text = "port";
            this.label5.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(10, 40);
            this.label6.Name = "label6";
            this.label6.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.label6.Size = new System.Drawing.Size(42, 13);
            this.label6.TabIndex = 3;
            this.label6.Text = "runs on";
            this.label6.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // comboBoxClientAddress
            // 
            this.comboBoxClientAddress.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBoxClientAddress.FormattingEnabled = true;
            this.comboBoxClientAddress.Location = new System.Drawing.Point(58, 38);
            this.comboBoxClientAddress.Name = "comboBoxClientAddress";
            this.comboBoxClientAddress.Size = new System.Drawing.Size(201, 21);
            this.comboBoxClientAddress.TabIndex = 2;
            // 
            // buttonPlus
            // 
            this.buttonPlus.BackColor = System.Drawing.SystemColors.MenuHighlight;
            this.buttonPlus.Location = new System.Drawing.Point(164, 11);
            this.buttonPlus.Name = "buttonPlus";
            this.buttonPlus.Size = new System.Drawing.Size(95, 23);
            this.buttonPlus.TabIndex = 10;
            this.buttonPlus.Text = "Local debug (+)";
            this.buttonPlus.UseVisualStyleBackColor = false;
            this.buttonPlus.Click += new System.EventHandler(this.ButtonPlus_Click);
            // 
            // checkBoxServer
            // 
            this.checkBoxServer.AutoSize = true;
            this.checkBoxServer.CheckAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.checkBoxServer.Location = new System.Drawing.Point(199, 15);
            this.checkBoxServer.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.checkBoxServer.Name = "checkBoxServer";
            this.checkBoxServer.Size = new System.Drawing.Size(57, 17);
            this.checkBoxServer.TabIndex = 11;
            this.checkBoxServer.Text = "Server";
            this.checkBoxServer.UseVisualStyleBackColor = true;
            this.checkBoxServer.CheckedChanged += new System.EventHandler(this.CheckBoxServer_CheckedChanged);
            // 
            // checkBoxClient
            // 
            this.checkBoxClient.AutoSize = true;
            this.checkBoxClient.Location = new System.Drawing.Point(5, 17);
            this.checkBoxClient.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.checkBoxClient.Name = "checkBoxClient";
            this.checkBoxClient.Size = new System.Drawing.Size(52, 17);
            this.checkBoxClient.TabIndex = 12;
            this.checkBoxClient.Text = "Client";
            this.checkBoxClient.UseVisualStyleBackColor = true;
            this.checkBoxClient.CheckedChanged += new System.EventHandler(this.CheckBoxClient_CheckedChanged);
            // 
            // groupBoxMethod
            // 
            this.groupBoxMethod.Controls.Add(this.label9);
            this.groupBoxMethod.Controls.Add(this.listBoxMethod);
            this.groupBoxMethod.Controls.Add(this.textBoxSecret);
            this.groupBoxMethod.Controls.Add(this.label7);
            this.groupBoxMethod.Location = new System.Drawing.Point(12, 124);
            this.groupBoxMethod.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.groupBoxMethod.Name = "groupBoxMethod";
            this.groupBoxMethod.Padding = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.groupBoxMethod.Size = new System.Drawing.Size(541, 199);
            this.groupBoxMethod.TabIndex = 14;
            this.groupBoxMethod.TabStop = false;
            this.groupBoxMethod.Text = "Message handling";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(4, 16);
            this.label9.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(248, 13);
            this.label9.TabIndex = 18;
            this.label9.Text = "Available fields (multiselection - use CTRL / SHIFT)";
            // 
            // listBoxMethod
            // 
            this.listBoxMethod.FormattingEnabled = true;
            this.listBoxMethod.Location = new System.Drawing.Point(7, 31);
            this.listBoxMethod.Name = "listBoxMethod";
            this.listBoxMethod.ScrollAlwaysVisible = true;
            this.listBoxMethod.SelectionMode = System.Windows.Forms.SelectionMode.MultiExtended;
            this.listBoxMethod.Size = new System.Drawing.Size(255, 160);
            this.listBoxMethod.TabIndex = 17;
            // 
            // textBoxSecret
            // 
            this.textBoxSecret.Location = new System.Drawing.Point(276, 31);
            this.textBoxSecret.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.textBoxSecret.Multiline = true;
            this.textBoxSecret.Name = "textBoxSecret";
            this.textBoxSecret.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.textBoxSecret.Size = new System.Drawing.Size(259, 160);
            this.textBoxSecret.TabIndex = 15;
            this.textBoxSecret.Text = "VSB - Technical University of Ostrava has long tradition in high quality engineer" +
    "ing.";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(273, 16);
            this.label7.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(88, 13);
            this.label7.TabIndex = 16;
            this.label7.Text = "Secret to transfer";
            // 
            // textBoxDestination
            // 
            this.textBoxDestination.Location = new System.Drawing.Point(58, 84);
            this.textBoxDestination.Name = "textBoxDestination";
            this.textBoxDestination.Size = new System.Drawing.Size(201, 20);
            this.textBoxDestination.TabIndex = 18;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(5, 86);
            this.label8.Name = "label8";
            this.label8.RightToLeft = System.Windows.Forms.RightToLeft.Yes;
            this.label8.Size = new System.Drawing.Size(48, 13);
            this.label8.TabIndex = 17;
            this.label8.Text = "to where";
            this.label8.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.textBoxDestination);
            this.groupBox1.Controls.Add(this.buttonPlus);
            this.groupBox1.Controls.Add(this.label8);
            this.groupBox1.Controls.Add(this.checkBoxClient);
            this.groupBox1.Controls.Add(this.comboBoxClientAddress);
            this.groupBox1.Controls.Add(this.label6);
            this.groupBox1.Controls.Add(this.label5);
            this.groupBox1.Controls.Add(this.numericUpDownClientPort);
            this.groupBox1.Location = new System.Drawing.Point(287, 10);
            this.groupBox1.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.groupBox1.Size = new System.Drawing.Size(266, 109);
            this.groupBox1.TabIndex = 15;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Client network";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.comboBoxServerAddress);
            this.groupBox2.Controls.Add(this.label1);
            this.groupBox2.Controls.Add(this.label2);
            this.groupBox2.Controls.Add(this.numericUpDownServerPort);
            this.groupBox2.Controls.Add(this.checkBoxServer);
            this.groupBox2.Location = new System.Drawing.Point(12, 12);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(261, 107);
            this.groupBox2.TabIndex = 17;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Server network";
            // 
            // backgroundWorkerDebugPrinter
            // 
            this.backgroundWorkerDebugPrinter.DoWork += new System.ComponentModel.DoWorkEventHandler(this.BackgroundWorkerDebugPrinter_DoWork);
            // 
            // MainWindow
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1069, 405);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.groupBoxClient);
            this.Controls.Add(this.groupBoxMethod);
            this.Controls.Add(this.textBoxDebug);
            this.Controls.Add(this.groupBoxServer);
            this.Name = "MainWindow";
            this.Text = "Network Steganography Tool";
            this.groupBoxServer.ResumeLayout(false);
            this.groupBoxServer.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownServerPort)).EndInit();
            this.groupBoxClient.ResumeLayout(false);
            this.groupBoxClient.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.numericUpDownClientPort)).EndInit();
            this.groupBoxMethod.ResumeLayout(false);
            this.groupBoxMethod.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.GroupBox groupBoxServer;
        private System.Windows.Forms.Button buttonListen;
        public System.Windows.Forms.TextBox textBoxDebug;
        private System.Windows.Forms.NumericUpDown numericUpDownServerPort;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBoxServerStatus;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.GroupBox groupBoxClient;
        public System.Windows.Forms.TextBox textBoxClientStatus;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.NumericUpDown numericUpDownClientPort;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.ComboBox comboBoxClientAddress;
        private System.Windows.Forms.Button buttonPlus;
        private System.Windows.Forms.CheckBox checkBoxServer;
        private System.Windows.Forms.CheckBox checkBoxClient;
        private System.Windows.Forms.GroupBox groupBoxMethod;
        private System.Windows.Forms.Button buttonClient;
        private System.Windows.Forms.TextBox textBoxSecret;
        private System.Windows.Forms.Label label7;
        public System.Windows.Forms.ComboBox comboBoxServerAddress;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.TextBox textBoxDestination;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.ListBox listBoxMethod;
        private System.Windows.Forms.Label label9;
        private System.ComponentModel.BackgroundWorker backgroundWorkerDebugPrinter;
    }
}

